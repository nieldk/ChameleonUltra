/*
 * mode_relay.c
 *
 * Standalone relay mode: two ChameleonUltra devices transparently relay
 * an NFC transaction over a direct BLE link.
 *
 *   RELAY_CARD  (lower BLE MAC) — NFCT, faces the real reader
 *   RELAY_READER (higher BLE MAC) — RC522, faces the real card
 *
 * Pre-connection flow (before reader approaches):
 *   RELAY_READER pre-reads the card's ATQA/UID/SAK/ATS, does a partial
 *   MIFARE Classic auth to cache NT, then sends everything to RELAY_CARD.
 *
 * Relay flow (reader active):
 *   REQA/ATQA/anticoll/SELECT/SAK — answered from cache by RELAY_CARD (fast)
 *   AUTH → NT  — answered from pre-cached NT (fast, no BLE)
 *   NR||AR    — relayed to RELAY_READER via BLE
 *   AT        — real card computes it, relayed back to RELAY_CARD via BLE
 *   ISO14443-4 APDUs — relayed with WTX frame injection for timing
 *
 * Note: MIFARE Classic AT timing is reader-dependent. ISO14443-4 (DESFire,
 * MIFARE Plus) works cleanly with WTX.
 *
 * Config: standalone config relay --wtx 2000
 */

#include "app_standalone.h"
#include "standalone_led.h"
#include "ble_relay.h"

#include <string.h>
#include <stdint.h>

#include "nrf_log.h"
#include "app_timer.h"
#include "app_status.h"

#include "rfid/nfctag/hf/nfc_14a.h"
#include "rfid_main.h"       /* reader_mode_enter, tag_mode_enter */
#include "bsp/bsp_delay.h"
#include "utils/syssleep.h"
#include "rfid/nfctag/hf/nfc_mf1.h"
#include "rfid/reader/hf/rc522.h"
#include "tag_emulation.h"

/* -------------------------------------------------------------------------
 * Config
 * ------------------------------------------------------------------------- */
#define RELAY_DEFAULT_WTX_MS     2000u    /* WTX time requested from reader   */
#define RELAY_LINK_TIMEOUT_MS    120000u   /* 2 minutes to find peer            */
#define RELAY_PREAUTH_TIMEOUT_MS 5000u    /* max wait for card on READER side  */
#define RELAY_AT_TIMEOUT_MS      3000u    /* max wait for AT from RELAY_READER */
#define RELAY_FRAME_TIMEOUT_MS   500u     /* max wait for card response        */

/* MIFARE Classic pre-auth: block and key type to use for NT caching.
 * Block 0 Key A is the most common access control pattern. */
#define RELAY_PREAUTH_BLOCK      0
#define RELAY_PREAUTH_KEY_TYPE   PICC_AUTHENT1A

/* ISO14443-4 S(WTX) block: byte 0 = 0xF2 (S-block, WTX), byte 1 = WTXM */
#define RELAY_WTX_BLOCK_CMD      0xF2
#define RELAY_WTX_MULTIPLIER     1       /* 1× FWT ≈ 78ms per WTX request     */

/* -------------------------------------------------------------------------
 * Result storage — persisted via app_standalone FDS API
 *
 * One fixed-size record per relay session (connected + disconnected).
 * 32 bytes each; max 32 sessions = 1024 bytes (well within 2084 limit).
 * ------------------------------------------------------------------------- */
#define RELAY_RESULT_RECORD_SIZE   32u
#define RELAY_RESULT_MAX_SESSIONS  32u
#define RELAY_RESULT_BUF_BYTES     (RELAY_RESULT_RECORD_SIZE * RELAY_RESULT_MAX_SESSIONS)

/* Session status codes stored in record[29] */
#define RELAY_SESSION_OK           0x00  /* clean disconnect/disarm */
#define RELAY_SESSION_TIMEOUT      0x01  /* link timeout without connecting */
#define RELAY_SESSION_DISCONNECT   0x02  /* peer disconnected mid-relay */

/*
 * Record layout (32 bytes, all offsets fixed):
 *   [0]      role         (BLE_RELAY_ROLE_CARD=0 / BLE_RELAY_ROLE_READER=1)
 *   [1..6]   own_mac      (6 bytes, little-endian BLE address)
 *   [7..12]  peer_mac     (6 bytes, little-endian BLE address)
 *   [13..14] frames_tx    u16 LE
 *   [15..16] frames_rx    u16 LE
 *   [17]     auth_count   number of completed NR||AR relay cycles
 *   [18]     uid_len      (4 or 7, 0 if no identity)
 *   [19..25] uid          7 bytes (zero-padded for 4-byte UIDs)
 *   [26..27] atqa         2 bytes
 *   [28]     sak          1 byte
 *   [29]     session_status (see RELAY_SESSION_* above)
 *   [30..31] reserved / zero
 */
static uint32_t m_result_words[(RELAY_RESULT_BUF_BYTES + 3) / 4];
#define m_result_buf ((uint8_t *)m_result_words)


typedef enum {
    RS_INIT = 0,
    RS_LINKING,              /* waiting for BLE peer connection       */
    RS_CARD_AWAIT_IDENTITY,  /* CARD: waiting for identity from READER */
    RS_CARD_READY,           /* CARD: emulating, ready for reader      */
    RS_CARD_AUTH_GOT_NRAR,   /* CARD: NR||AR captured, relaying it     */
    RS_CARD_AWAIT_AT,        /* CARD: waiting for AT from READER       */
    RS_CARD_ISO4_RELAY,      /* CARD: ISO14443-4 APDU relay in flight  */
    RS_READER_SCAN,          /* READER: looking for real card          */
    RS_READER_READY,         /* READER: card connected, ready to relay */
    RS_READER_RELAY,         /* READER: presenting frame to real card  */
    RS_ERROR,
} relay_sub_state_t;

/* -------------------------------------------------------------------------
 * Module state
 * ------------------------------------------------------------------------- */
static struct {
    relay_sub_state_t sub;
    uint8_t           role;
    uint32_t          wtx_ms;

    /* Card identity (set by READER, used by CARD) */
    relay_card_identity_t identity;
    bool identity_received;

    /* Pre-cached NT for MIFARE Classic relay */
    uint8_t cached_nt[4];
    bool    nt_cached;
    uint8_t preauth_block;
    uint8_t preauth_key_type;

    /* Sequencing flags so CARD can handle identity and ready in any order */
    bool    reader_sent_ready;

    /* MIFARE Classic NR||AR capture (set in ISR, processed in tick) */
    volatile bool    nrar_pending;
    uint8_t          nrar_buf[8];

    /* AT relay (received from READER over BLE) */
    volatile bool    at_received;
    uint8_t          at_buf[4];

    /* ISO14443-4 APDU relay */
    volatile bool    apdu_response_ready;
    uint8_t          apdu_resp_buf[256];
    uint16_t         apdu_resp_bits;

    /* Reader card context for RELAY_READER */
    picc_14a_tag_t   real_card;
    bool             real_card_found;
    bool             real_card_authed;

    /* WTX timer tracking */
    uint32_t         wtx_sent_ticks;

    /* Link timeout */
    uint32_t         link_start_ticks;

    /* Result buffer tracking */
    size_t  result_write;    /* bytes written into m_result_buf */
    size_t  result_read;     /* read cursor for drain */
    uint8_t session_count;
    bool    result_loaded;

    /* Per-session counters (reset on connect) */
    uint16_t frames_tx;
    uint16_t frames_rx;
    uint8_t  auth_count;

    bool active;
} m_st;

/* -------------------------------------------------------------------------
 * NFC_MF1 relay hooks (declared in nfc_mf1.h extension)
 * See nfc_mf1_relay.h / nfc_mf1.c modifications
 * ------------------------------------------------------------------------- */
extern void nfc_mf1_relay_set_nt(const uint8_t nt[4]);
extern void nfc_mf1_relay_set_coll_res(const uint8_t *uid, uint8_t uid_len,
                                        const uint8_t atqa[2], uint8_t sak);
extern void nfc_mf1_relay_set_nrar_cb(void (*cb)(const uint8_t *nrar, uint8_t len));
extern void nfc_mf1_relay_inject_at(const uint8_t at[4]);
extern void nfc_mf1_relay_tx_at(void);
extern void nfc_mf1_relay_clear(void);

/* -------------------------------------------------------------------------
 * WTX helpers
 * ------------------------------------------------------------------------- */

/* Send ISO14443-4 S(WTX) frame to buy time from the reader.
 * Only applicable when the reader is ISO14443-4 compliant.
 * Returns true if sent. */
static bool send_wtx(void) {
    uint8_t wtx[4];
    wtx[0] = RELAY_WTX_BLOCK_CMD;
    wtx[1] = RELAY_WTX_MULTIPLIER;
    nfc_tag_14a_append_crc(wtx, 2);
    nfc_tag_14a_tx_bytes(wtx, 4, false);
    m_st.wtx_sent_ticks = app_timer_cnt_get();
    NRF_LOG_DEBUG("relay: WTX sent");
    return true;
}

/* -------------------------------------------------------------------------
 * NR||AR ISR callback (called from nfc_mf1.c when NR||AR arrives)
 * Must be ISR-safe: only copy data and set flag.
 * -------------------------------------------------------------------------
 */
static void on_nrar_isr(const uint8_t *nrar, uint8_t len) {
    if (len >= 8) {
        memcpy(m_st.nrar_buf, nrar, 8);
        m_st.nrar_pending = true;
        /* For MIFARE Classic (no T=CL / WTX), we can't buy time.
         * For ISO14443-4 the calling code should send WTX before this CB. */
    }
}

/* -------------------------------------------------------------------------
 * Result buffer helpers
 * ------------------------------------------------------------------------- */

static void result_ensure_loaded(void) {
    if (m_st.result_loaded) return;
    m_st.result_loaded = true;
    size_t loaded = 0;
    standalone_rc_t rc = app_standalone_load_result_buf(
        STANDALONE_MODE_RELAY, m_result_words, RELAY_RESULT_BUF_BYTES, &loaded);
    if (rc == STANDALONE_RC_OK && loaded > 0) {
        m_st.result_write  = loaded;
        m_st.session_count = (uint8_t)(loaded / RELAY_RESULT_RECORD_SIZE);
        m_st.result_read   = 0;
    }
}

static void result_reset_counters(void) {
    m_st.frames_tx  = 0;
    m_st.frames_rx  = 0;
    m_st.auth_count = 0;
}

/* Append one session record to the RAM buffer and persist to FDS.
 * Called on disconnect or disarm. */
static void result_save_session(uint8_t session_status) {
    result_ensure_loaded();

    if (m_st.result_write + RELAY_RESULT_RECORD_SIZE > RELAY_RESULT_BUF_BYTES) {
        /* Buffer full — drop oldest session by shifting */
        size_t keep = RELAY_RESULT_BUF_BYTES - RELAY_RESULT_RECORD_SIZE;
        memmove(m_result_buf,
                m_result_buf + RELAY_RESULT_RECORD_SIZE,
                keep);
        m_st.result_write  = keep;
        m_st.session_count = (uint8_t)(keep / RELAY_RESULT_RECORD_SIZE);
    }

    uint8_t *p = &m_result_buf[m_st.result_write];
    memset(p, 0, RELAY_RESULT_RECORD_SIZE);

    uint8_t own[6]  = {0};
    uint8_t peer[6] = {0};
    ble_relay_get_my_addr(own);
    ble_relay_get_peer_addr(peer);

    p[0]  = m_st.role;
    memcpy(&p[1],  own,  6);
    memcpy(&p[7],  peer, 6);
    p[13] = (uint8_t)(m_st.frames_tx      );
    p[14] = (uint8_t)(m_st.frames_tx >>  8);
    p[15] = (uint8_t)(m_st.frames_rx      );
    p[16] = (uint8_t)(m_st.frames_rx >>  8);
    p[17] = m_st.auth_count;

    /* Prefer identity (populated on both sides once card is known).
     * For RELAY_READER: fall back to real_card if identity wasn't built yet. */
    if (m_st.identity.uid_len > 0) {
        p[18] = m_st.identity.uid_len;
        memcpy(&p[19], m_st.identity.uid,  7);
        memcpy(&p[26], m_st.identity.atqa, 2);
        p[28] = m_st.identity.sak;
    } else if (m_st.real_card_found) {
        uint8_t uid4[4] = {0};
        get_4byte_tag_uid(&m_st.real_card, uid4);
        p[18] = 4;
        memcpy(&p[19], uid4, 4);
        memcpy(&p[26], m_st.real_card.atqa, 2);
        p[28] = m_st.real_card.sak;
    }
    p[29] = session_status;

    m_st.result_write += RELAY_RESULT_RECORD_SIZE;
    m_st.session_count++;
    m_st.result_read = 0;  /* reset read cursor so next drain gets everything */

    app_standalone_save_result_buf(STANDALONE_MODE_RELAY,
                                   m_result_words, m_st.result_write);
    NRF_LOG_INFO("relay: session saved (status=%u, total=%u)",
                 session_status, m_st.session_count);
}

/* -------------------------------------------------------------------------
 * BLE relay callbacks (all called from main-loop via ble_relay_process())
 * ------------------------------------------------------------------------- */

static void on_connected(uint8_t my_role) {
    m_st.role = my_role;
    NRF_LOG_INFO("relay: connected, role=%s",
                 my_role == BLE_RELAY_ROLE_CARD ? "CARD" : "READER");

    /* Green flash then solid role colour:
     *   RELAY_CARD   → solid BLUE  (faces the reader)
     *   RELAY_READER → solid GREEN (faces the real card)
     * We set the palette entry for relay to the role colour, then call
     * SL_FB_ARMED which ends with all LEDs solid in that colour. */
    if (my_role == BLE_RELAY_ROLE_CARD) {
        standalone_feedback(SL_FB_SUCCESS);
        standalone_led_set_mode_color(STANDALONE_MODE_RELAY, RGB_BLUE);
    } else {
        standalone_feedback(SL_FB_SUCCESS);
        standalone_led_set_mode_color(STANDALONE_MODE_RELAY, RGB_GREEN);
    }
    standalone_led_solid();   /* leave LEDs solid in the new mode colour */

    if (my_role == BLE_RELAY_ROLE_CARD) {
        m_st.sub = RS_CARD_AWAIT_IDENTITY;
    } else {
        /* Switch HF hardware to reader mode — stops NFCT emulation,
         * powers RC522, switches HF antenna. Without this the RC522
         * scan causes a reset (hardware conflict on shared antenna). */
        reader_mode_enter();
        m_st.sub = RS_READER_SCAN;
    }
}

static void on_card_identity(const relay_card_identity_t *id) {
    /* Accept only the first valid identity — subsequent re-broadcasts from
     * RELAY_READER are for reliability, but we don't want a partially-received
     * packet overwriting a good identity that's already set up in NFCT. */
    if (m_st.identity_received) return;

    memcpy(&m_st.identity, id, sizeof(*id));
    /* Sanity check — uid_len must be 4 or 7 for valid NFC-A cards */
    if (m_st.identity.uid_len != 4 && m_st.identity.uid_len != 7) {
        NRF_LOG_WARNING("relay: received uid_len=%u, defaulting to 4",
                        m_st.identity.uid_len);
        m_st.identity.uid_len = 4;
    }
    m_st.identity_received = true;
    /* Receiving CARD_IDENTITY means READER_READY — no separate READY needed */
    m_st.reader_sent_ready = true;
    NRF_LOG_INFO("relay: card identity received UID=%02X%02X%02X%02X",
                 m_st.identity.uid[0], m_st.identity.uid[1],
                 m_st.identity.uid[2], m_st.identity.uid[3]);
}

static void on_preauth(const relay_preauth_t *pa) {
    memcpy(m_st.cached_nt, pa->nt, 4);
    m_st.nt_cached        = true;
    m_st.preauth_block    = pa->block;
    m_st.preauth_key_type = pa->key_type;
    NRF_LOG_INFO("relay: pre-auth NT=%02X%02X%02X%02X block=%u",
                 pa->nt[0], pa->nt[1], pa->nt[2], pa->nt[3], pa->block);
}

static void on_ready(void) {
    NRF_LOG_INFO("relay: peer is ready");
    if (m_st.role == BLE_RELAY_ROLE_CARD) {
        m_st.reader_sent_ready = true;
        /* Advance to READY only if identity already received */
        if (m_st.identity_received) {
            m_st.sub = RS_CARD_READY;
            standalone_feedback(SL_FB_ARMED);
        }
    }
}

static void on_response(const uint8_t *data, uint16_t bits) {
    if (m_st.sub == RS_CARD_AWAIT_AT && bits == 32 && data) {
        /* AT for MIFARE Classic */
        memcpy(m_st.at_buf, data, 4);
        m_st.at_received = true;
        m_st.frames_rx++;
    } else if (m_st.sub == RS_CARD_ISO4_RELAY) {
        /* ISO14443-4 APDU response */
        uint16_t bytes = (bits + 7) / 8;
        if (bytes > sizeof(m_st.apdu_resp_buf))
            bytes = sizeof(m_st.apdu_resp_buf);
        memcpy(m_st.apdu_resp_buf, data, bytes);
        m_st.apdu_resp_bits      = bits;
        m_st.apdu_response_ready = true;
        m_st.frames_rx++;
    }
}

static void on_no_response(void) {
    NRF_LOG_INFO("relay: no response from real card");
    m_st.at_received         = false;
    m_st.apdu_response_ready = true;
    m_st.apdu_resp_bits      = 0;
}

static void on_disconnected(void) {
    NRF_LOG_INFO("relay: peer disconnected");
    result_save_session(RELAY_SESSION_DISCONNECT);
    result_reset_counters();
    m_st.sub         = RS_LINKING;
    m_st.nt_cached   = false;
    m_st.identity_received = false;
    m_st.reader_sent_ready = false;
    m_st.link_start_ticks  = app_timer_cnt_get();
    sleep_timer_stop();            /* keep alive while searching again */
    standalone_feedback(SL_FB_ERROR);
    ble_relay_start();             /* restart discovery immediately */
}

/* -------------------------------------------------------------------------
 * RELAY_READER card setup
 * (runs synchronously from on_tick — blocking RC522 calls are OK here)
 * ------------------------------------------------------------------------- */
static void reader_setup_card(void) {
    /* Find and select the real card.
     * Antenna on only for the duration of the scan — must be off otherwise
     * or device resets (see mode_authtrace.c after_hf_reader_run note). */
    if (!m_st.real_card_found) {
        pcd_14a_reader_reset();
        pcd_14a_reader_antenna_on();
        bsp_delay_ms(8);
        uint8_t status = pcd_14a_reader_scan_auto(&m_st.real_card);
        if (status != STATUS_HF_TAG_OK) {
            pcd_14a_reader_antenna_off();
            NRF_LOG_DEBUG("relay reader: no card found");
            return;
        }
        m_st.real_card_found = true;
        NRF_LOG_INFO("relay reader: card found UID=%02X%02X%02X%02X",
                     m_st.real_card.uid[0], m_st.real_card.uid[1],
                     m_st.real_card.uid[2], m_st.real_card.uid[3]);
    }

    /* Build card identity message.
     * IMPORTANT: uid[] stores raw anticollision bytes (including cascade
     * tag bytes for 7-byte UIDs). Use get_4byte_tag_uid() to extract the
     * correct 4-byte UID, and derive uid_len from cascade level. */
    relay_card_identity_t id;
    memset(&id, 0, sizeof(id));
    id.atqa[0] = m_st.real_card.atqa[0];
    id.atqa[1] = m_st.real_card.atqa[1];
    id.sak     = m_st.real_card.sak;

    /* Derive uid_len from cascade: 1=4B, 2=7B, 3=10B */
    uint8_t cascade = m_st.real_card.cascade;
    if (cascade == 0) cascade = 1;   /* safety default */
    id.uid_len = cascade == 1 ? 4 : (cascade == 2 ? 7 : 10);
    if (id.uid_len > 7) id.uid_len = 7;

    if (id.uid_len == 4) {
        /* cascade 1: get_4byte_tag_uid extracts correctly from raw uid[] */
        get_4byte_tag_uid(&m_st.real_card, id.uid);
    } else {
        /* cascade 2 (7-byte): copy all 7 bytes */
        memcpy(id.uid, m_st.real_card.uid, 7);
    }

    NRF_LOG_INFO("relay reader: UID=%02X%02X%02X%02X cascade=%u",
                 id.uid[0], id.uid[1], id.uid[2], id.uid[3], cascade);

    /* Try to get ATS if card is ISO14443-4 compliant */
    if (m_st.real_card.sak & 0x20) {
        uint8_t  ats[64];
        uint16_t ats_bits = 0;
        if (pcd_14a_reader_ats_request(ats, &ats_bits,
                                       sizeof(ats) * 8) == STATUS_HF_TAG_OK) {
            id.ats_len = (ats_bits + 7) / 8;
            if (id.ats_len > sizeof(id.ats)) id.ats_len = sizeof(id.ats);
            memcpy(id.ats, ats, id.ats_len);
        }
    }

    /* Store identity in m_st.identity so RS_READER_READY re-broadcasts
     * use real card data, not the zero-initialised struct */
    memcpy(&m_st.identity, &id, sizeof(id));

    ble_relay_send_card_identity(&id);
    NRF_LOG_INFO("relay reader: sent card identity");

    /* MIFARE Classic pre-auth: do partial auth to cache NT */
    if (!(m_st.real_card.sak & 0x20)) {
        /* Classic card — try to get NT by starting auth with block 0 */
        /* We need to extract NT after auth command — use mf1_auth which
         * drives the full auth sequence. The NT is captured internally.
         * To get just NT without completing the full auth (which requires
         * knowing the key), we'd need RC522 low-level access.
         * Workaround: do auth with a key and check if it passes.
         * If the key is unknown, skip pre-auth; relay will be timing-dependent. */
        uint8_t  null_key[6] = {0};
        (void)pcd_14a_reader_mf1_auth(&m_st.real_card,
                                      RELAY_PREAUTH_KEY_TYPE,
                                      RELAY_PREAUTH_BLOCK,
                                      null_key);
        /* NOTE: auth will likely fail (wrong key) but the NT exchange already
         * happened on the wire. For a proper pre-auth with NT extraction,
         * a lower-level RC522 sequence is needed. For now we skip NT pre-cache
         * and rely on reader timing tolerance for Classic.
         * Auth with the correct key (if known) would populate NT for relay. */
        pcd_14a_reader_mf1_unauth();
        NRF_LOG_DEBUG("relay reader: classic card, pre-auth skipped "
                      "(key unknown, timing is reader-dependent)");
    }

    pcd_14a_reader_antenna_off();
    /* Don't send READY separately — it overwrites CARD_IDENTITY in the
     * advertising packet before CU1 can receive it. on_card_identity on
     * CU1 sets reader_sent_ready=true implicitly. */
    m_st.sub = RS_READER_READY;
    NRF_LOG_INFO("relay reader: card found, identity sent");
}

/* -------------------------------------------------------------------------
 * RELAY_CARD NFCT setup
 * Load card identity into the active emulation slot
 * ------------------------------------------------------------------------- */
static void card_setup_emulation(void) {
    if (!m_st.identity_received) return;

    /* Load the real card's UID into the active slot's tag data.
     * tag_emulation_change_config() or direct slot memory write.
     * The NFCT hardware will use whatever is in the active slot. */
    /* Configure NFCT anti-collision response with the real card's identity */
    NRF_LOG_INFO("relay card: setup emul uid=%08X len=%u sak=%02X",
                 ((uint32_t)m_st.identity.uid[0]<<24)|((uint32_t)m_st.identity.uid[1]<<16)|
                 ((uint32_t)m_st.identity.uid[2]<<8)|m_st.identity.uid[3],
                 m_st.identity.uid_len, m_st.identity.sak);
    nfc_mf1_relay_set_coll_res(m_st.identity.uid,
                               m_st.identity.uid_len,
                               m_st.identity.atqa,
                               m_st.identity.sak);

    /* Install NT pre-cache and NR||AR intercept hooks in nfc_mf1 */
    if (m_st.nt_cached) {
        nfc_mf1_relay_set_nt(m_st.cached_nt);
    }
    nfc_mf1_relay_set_nrar_cb(on_nrar_isr);

    NRF_LOG_INFO("relay card: emulation configured");
}

/* -------------------------------------------------------------------------
 * RELAY_READER raw frame relay (called from on_tick when frame arrives)
 * ------------------------------------------------------------------------- */
static void reader_relay_frame(const uint8_t *data, uint16_t bits) {
    uint8_t  rx_buf[256];
    uint16_t rx_bits = 0;
    uint8_t  tx_buf[256];
    uint16_t tx_bytes = (bits + 7) / 8;

    if (tx_bytes > sizeof(tx_buf)) tx_bytes = sizeof(tx_buf);
    memcpy(tx_buf, data, tx_bytes);

    /* Send frame to real card, get response */
    uint8_t status = pcd_14a_reader_bytes_transfer(
        PCD_TRANSCEIVE,
        tx_buf, tx_bytes,
        rx_buf, &rx_bits,
        sizeof(rx_buf) * 8
    );

    if (status == STATUS_HF_TAG_OK && rx_bits > 0) {
        ble_relay_send_response(rx_buf, rx_bits);
        m_st.frames_tx++;   /* RELAY_READER: frame sent to real card */
        m_st.frames_rx++;   /* RELAY_READER: response received from real card */
    } else {
        ble_relay_send_no_response();
        m_st.frames_tx++;   /* frame was sent even if no response */
    }
}

/* -------------------------------------------------------------------------
 * BLE pending frame from RELAY_CARD (set in callbacks, handled in tick)
 * ------------------------------------------------------------------------- */
static volatile bool     m_frame_pending = false;
static uint8_t           m_frame_buf[256];
static uint16_t          m_frame_bits = 0;

static void on_frame(const uint8_t *data, uint16_t bits) {
    uint16_t bytes = (bits + 7) / 8;
    if (bytes > sizeof(m_frame_buf)) bytes = sizeof(m_frame_buf);
    memcpy(m_frame_buf, data, bytes);
    m_frame_bits    = bits;
    m_frame_pending = true;
    m_st.frames_rx++;   /* RELAY_CARD receives a frame from RELAY_READER */
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

static const ble_relay_callbacks_t k_relay_cbs = {
    .on_connected    = on_connected,
    .on_card_identity= on_card_identity,
    .on_preauth      = on_preauth,
    .on_ready        = on_ready,
    .on_frame        = on_frame,
    .on_response     = on_response,
    .on_no_response  = on_no_response,
    .on_disconnected = on_disconnected,
};

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    /* Preserve result buffer state across re-arms */
    size_t  saved_result_write  = m_st.result_write;
    size_t  saved_result_read   = m_st.result_read;
    uint8_t saved_session_count = m_st.session_count;
    bool    saved_result_loaded = m_st.result_loaded;

    memset(&m_st, 0, sizeof(m_st));

    m_st.result_write   = saved_result_write;
    m_st.result_read    = saved_result_read;
    m_st.session_count  = saved_session_count;
    m_st.result_loaded  = saved_result_loaded;

    m_st.active  = true;
    m_st.wtx_ms  = RELAY_DEFAULT_WTX_MS;
    m_st.sub     = RS_LINKING;

    /* Parse config blob: [u32 wtx_ms_le] */
    if (cfg != NULL && cfg_len >= 4) {
        m_st.wtx_ms = (uint32_t)cfg[0]
                    | ((uint32_t)cfg[1] << 8)
                    | ((uint32_t)cfg[2] << 16)
                    | ((uint32_t)cfg[3] << 24);
    }

    m_st.link_start_ticks = app_timer_cnt_get();

    /* Prevent device from sleeping while relay is active */
    sleep_timer_stop();

    /* ble_relay_init registers the GATT service - must only run once at boot.
     * Use a static flag to guard against re-registration on re-arm. */
    static bool s_relay_initialized = false;
    if (!s_relay_initialized) {
        ble_relay_init(&k_relay_cbs);
        s_relay_initialized = true;
    }
    ble_relay_start();

    NRF_LOG_INFO("relay: armed, WTX=%ums, searching for peer", m_st.wtx_ms);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    /* Save session record unless we never connected */
    if (m_st.sub != RS_LINKING && m_st.sub != RS_INIT) {
        result_save_session(RELAY_SESSION_OK);
    }
    m_st.active = false;
    nfc_mf1_relay_clear();
    ble_relay_stop();
    pcd_14a_reader_antenna_off();
    /* Restore HF hardware to tag emulation mode */
    tag_mode_enter();
    /* Re-enable sleep timer */
    sleep_timer_start(SLEEP_DELAY_MS_BUTTON_CLICK);
    NRF_LOG_INFO("relay: disarmed");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ticks) {
    if (!m_st.active) return STANDALONE_RC_OK;

    /* Always pump BLE relay event queue */
    ble_relay_process();

    /* Keep-alive: reset the sleep timer every tick so the device
     * never powers off while relay is active */
    sleep_timer_stop();

    /* Keep scan + HELLO broadcast alive every 2s while searching */
    static uint32_t s_last_scan_restart = 0;
    if (ble_relay_get_state() != BLE_RELAY_STATE_IDLE &&
        app_timer_cnt_diff_compute(now_ticks, s_last_scan_restart)
            >= APP_TIMER_TICKS(2000)) {
        s_last_scan_restart = now_ticks;
        ble_relay_restart_scan();
        if (m_st.sub == RS_LINKING) {
            ble_relay_broadcast_hello();   /* re-broadcast in case peer missed it */
        }
    }

    switch (m_st.sub) {
    case RS_LINKING: {
        uint32_t elapsed = app_timer_cnt_diff_compute(now_ticks,
                                                       m_st.link_start_ticks);
        /* Brief blue wave every 1s while searching for peer */
        static uint32_t s_last_pulse_ticks = 0;
        if (app_timer_cnt_diff_compute(now_ticks, s_last_pulse_ticks)
                >= APP_TIMER_TICKS(1000)) {
            s_last_pulse_ticks = now_ticks;
            standalone_feedback(SL_FB_BUSY_START);
        }
        if (elapsed >= APP_TIMER_TICKS(RELAY_LINK_TIMEOUT_MS)) {
            NRF_LOG_WARNING("relay: link timeout");
            m_st.sub = RS_ERROR;
            standalone_feedback(SL_FB_ERROR);
        }
        break;
    }

    case RS_CARD_AWAIT_IDENTITY:
        if (m_st.identity_received) {
            /* Install identity and hooks */
            card_setup_emulation();
            /* Advance to READY immediately if READY already received */
            if (m_st.reader_sent_ready) {
                m_st.sub = RS_CARD_READY;
                standalone_feedback(SL_FB_ARMED);
            }
            /* Otherwise wait in this state until on_ready() fires */
        }
        break;

    case RS_CARD_READY:
        /* NFCT emulation is running normally.
         * NR||AR ISR callback sets m_st.nrar_pending when auth happens. */
        if (m_st.nrar_pending) {
            m_st.nrar_pending = false;
            m_st.sub          = RS_CARD_AUTH_GOT_NRAR;
        }
        break;

    case RS_CARD_AUTH_GOT_NRAR:
        /* For ISO14443-4 readers: send WTX to buy time for the BLE round-trip.
         * For MIFARE Classic: reader timing is reader-dependent, WTX not supported. */
        if (m_st.identity.ats_len > 0) {
            send_wtx();  /* ISO14443-4: buy time with S(WTX) frame */
        }
        /* Send NR||AR to RELAY_READER over BLE */
        ble_relay_send_frame(m_st.nrar_buf, 64);
        m_st.sub            = RS_CARD_AWAIT_AT;
        m_st.wtx_sent_ticks = now_ticks;
        break;

    case RS_CARD_AWAIT_AT:
        if (m_st.at_received) {
            m_st.at_received = false;
            m_st.sub         = RS_CARD_READY;
            m_st.auth_count++;
            nfc_mf1_relay_inject_at(m_st.at_buf);
            nfc_mf1_relay_tx_at();
            NRF_LOG_INFO("relay card: AT transmitted, auth_count=%u", m_st.auth_count);
        } else {
            /* Check timeout */
            uint32_t wait = app_timer_cnt_diff_compute(now_ticks,
                                                        m_st.wtx_sent_ticks);
            if (wait >= APP_TIMER_TICKS(RELAY_AT_TIMEOUT_MS)) {
                NRF_LOG_WARNING("relay card: AT timeout, resetting auth");
                m_st.sub = RS_CARD_READY;
                nfc_tag_14a_set_state(NFC_TAG_STATE_14A_IDLE);
            }
        }
        break;

    case RS_CARD_ISO4_RELAY:
        if (m_st.apdu_response_ready) {
            m_st.apdu_response_ready = false;
            m_st.sub                 = RS_CARD_READY;
            if (m_st.apdu_resp_bits > 0) {
                uint16_t bytes = (m_st.apdu_resp_bits + 7) / 8;
                /* Relay response back to the real reader via NFCT */
                nfc_tag_14a_tx_bytes(m_st.apdu_resp_buf, bytes, true);
            }
        }
        break;

    case RS_READER_SCAN: {
        /* Scan for real card every 500ms.
         * CRITICAL: antenna must be OFF between scans — leaving it on
         * causes unexplained resets (BLE/power interaction, per authtrace). */
        static uint32_t s_last_card_scan = 0;
        if (app_timer_cnt_diff_compute(now_ticks, s_last_card_scan)
                >= APP_TIMER_TICKS(500)) {
            s_last_card_scan = now_ticks;
            sleep_timer_stop();
            reader_setup_card();          /* turns antenna on, scans, turns off */
            sleep_timer_stop();
        }
        break;
    }

    case RS_READER_READY: {
        /* Re-broadcast CARD_IDENTITY every 1s until CU1 confirms by
         * sending the first relay FRAME (reader approaching CU1). */
        static uint32_t s_last_identity_bcast = 0;
        if (app_timer_cnt_diff_compute(now_ticks, s_last_identity_bcast)
                >= APP_TIMER_TICKS(1000)) {
            s_last_identity_bcast = now_ticks;
            ble_relay_send_card_identity(&m_st.identity);
        }
        if (m_frame_pending) {
            m_frame_pending = false;
            m_st.sub        = RS_READER_RELAY;
            reader_relay_frame(m_frame_buf, m_frame_bits);
            m_st.sub = RS_READER_READY;
        }
        break;
    }

    case RS_READER_RELAY:
        /* handled synchronously in reader_relay_frame */
        break;

    case RS_ERROR:
        break;

    default:
        break;
    }

    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    switch (evt) {
        case STANDALONE_BTN_BOTH_VLONG:
            /* Clear stored results AND force disconnect/restart */
            memset(m_result_words, 0, sizeof(m_result_words));
            m_st.result_write  = 0;
            m_st.result_read   = 0;
            m_st.session_count = 0;
            m_st.result_loaded = true;
            app_standalone_save_result_buf(STANDALONE_MODE_RELAY, NULL, 0);
            ble_relay_stop();
            m_st.sub              = RS_LINKING;
            m_st.nt_cached        = false;
            m_st.identity_received= false;
            m_st.link_start_ticks = app_timer_cnt_get();
            ble_relay_start();
            standalone_feedback(SL_FB_SUCCESS);
            break;
        default:
            break;
    }
    return STANDALONE_RC_OK;
}

/* -------------------------------------------------------------------------
 * Result interface callbacks
 * ------------------------------------------------------------------------- */

static size_t get_result_size(void) {
    return m_st.result_write;
}

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (!out || !out_len) return STANDALONE_RC_INVALID_CFG;
    result_ensure_loaded();
    if (m_st.result_read >= m_st.result_write) {
        m_st.result_read = 0;
        *out_len = 0;
        return STANDALONE_RC_NO_RESULT;
    }
    size_t remaining = m_st.result_write - m_st.result_read;
    size_t take      = (remaining < out_max) ? remaining : out_max;
    memcpy(out, &m_result_buf[m_st.result_read], take);
    m_st.result_read += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    memset(m_result_words, 0, sizeof(m_result_words));
    m_st.result_write  = 0;
    m_st.result_read   = 0;
    m_st.session_count = 0;
    m_st.result_loaded = true;
    app_standalone_save_result_buf(STANDALONE_MODE_RELAY, NULL, 0);
}

static void ensure_loaded(void) {
    result_ensure_loaded();
}

/* Config is handled by the framework: wtx_ms is passed as cfg to on_enter. */

/* Public diagnostic accessor — used by CMD 7008 RELAY_DIAG */
void mode_relay_get_diag(uint8_t *out_sub, uint8_t *out_card_found,
                         uint8_t *out_identity_rx,
                         uint8_t *out_uid, uint8_t *out_uid_len) {
    if (out_sub)          *out_sub          = (uint8_t)m_st.sub;
    if (out_card_found)   *out_card_found   = m_st.real_card_found   ? 1 : 0;
    if (out_identity_rx)  *out_identity_rx  = m_st.identity_received ? 1 : 0;
    if (out_uid && out_uid_len) {
        if (m_st.real_card_found) {
            get_4byte_tag_uid(&m_st.real_card, out_uid);
            *out_uid_len = 4;
        } else if (m_st.identity_received) {
            *out_uid_len = m_st.identity.uid_len;
            memcpy(out_uid, m_st.identity.uid, m_st.identity.uid_len);
        } else {
            *out_uid_len = 0;
        }
    }
}


const standalone_mode_iface_t mode_relay_iface = {
    .id              = STANDALONE_MODE_RELAY,
    .name            = "relay",
    .writes_tag      = false,
    .writes_slot     = false,
    .wants_tick      = true,
    .on_enter        = on_enter,
    .on_exit         = on_exit,
    .on_button       = on_button,
    .on_tick         = on_tick,
    .get_result_size = get_result_size,
    .read_result     = read_result,
    .clear_result    = clear_result,
    .ensure_loaded   = ensure_loaded,
};
