#include "lf_hitag2_data.h"

#include <string.h>

#include "app_status.h"
#include "bsp_delay.h"
#include "hitag2_crypto.h"
#include "lf_hitag2_frame.h"
#include "lf_rdr_ia.h"
#include "lf_ia_codec.h"

#define NRF_LOG_MODULE_NAME lf_hitag2
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

/* -----------------------------------------------------------------------
 * Hitag2 reader on the interactive ADC reader engine (lf_rdr_ia.c): the
 * command goes out as field gaps inside a timeslot, the answer is captured
 * with the ADC (one sample per carrier period from the command's end) and
 * decoded from that recording. This replaces the earlier comparator-edge
 * receive path, which lost weak or blurred pulses the ADC still resolves.
 *
 * Command timings follow a Hitag2 reader's (proxmark3 armsrc/hitag2.c): a
 * gap of 6 carrier periods starts each bit, a 0 is 20 periods gap to gap and
 * a 1 is 30, a stop gap and 36 periods of field end the command. The tag
 * answers ~199-230 periods later in RF/32 Manchester behind 5 or 6 SOF ones.
 * --------------------------------------------------------------------- */

#define HT2_RESET_MS      20u          /* field off before a session: tag cold-starts */
#define HT2_POWER_UP_US   (371u * 8u)  /* field on this long before START_AUTH (313 powerup + margin) */
#define HT2_TRIES         8u           /* START_AUTHs per session: a tag answers only every second one */
#define HT2_PAGE_TRIES    6u           /* READ PAGEs per page, for two answers that agree (no CRC) */

static lf_rdr_link_t m_link = {
    .gap_us = 6u * 8u,
    /* Stopping and restarting the PWM adds ~14 us to each bit, so a 0 of 20
     * periods and a 1 of 30 are asked for that much shorter. */
    .bit0_us = 20u * 8u - 14u,
    .bit1_us = 30u * 8u - 14u,
    .eof_gap = 1u | LF_RDR_DAMP_GAPS,
    .stop_us = 36u * 8u,
    .coding = LF_IA_CODING_MANCHESTER,
    .coding_flags = 0,
    .bit_fc = 32,
    .window_us = 1000,
    .capture_n = LF_RDR_CAPTURE_MAX,
    .min_depth = 40,
    .slice_pct = 25,  /* the detector falls back from a load slowly: slice near the low rail */
};

/* SOF length and per-answer framing, learned once per session. */
static ht2_frame_t m_frame;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void bits_put(uint8_t *bits, size_t first, uint32_t v, size_t n) {
    for (size_t i = 0; i < n; i++) {
        lf_ia_bit_put(bits, first + i, (v >> (n - 1u - i)) & 1u);
    }
}

static void u32_be(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

/* 10-bit READ_PAGE/WRITE_PAGE frame: tx0 = opcode | (page<<3) | (comp>>2),
 * comp = page ^ 7; the low 2 bits of comp are the frame's last 2 bits.
 * Verified bit-for-bit against armsrc/hitag2.c's own sector decode. */
static uint16_t hitag2_page_frame(uint8_t opcode, uint8_t page) {
    uint8_t page3 = page & 0x7;
    uint8_t comp  = (page3 ^ 0x7) & 0x7;
    uint8_t tx0   = opcode | (page3 << 3) | (comp >> 2);
    return ((uint16_t)tx0 << 2) | (comp & 0x3);
}

/* One command/answer. tx is n bits (first bit first); the 32-bit answer page,
 * SOF stripped, is returned in *page. Returns false if the tag did not answer
 * or the answer did not frame. */
static bool exchange(const uint8_t *tx, size_t n, uint32_t power_up_us, uint32_t *page) {
    lf_rdr_reply_t rx;
    if (!lf_rdr_transact(&m_link, tx, n, power_up_us, &rx)) {
        return false;
    }
    return ht2_frame_page(&m_frame, rx.bits, rx.n_bits, rx.clean, page);
}

/* exchange() for a command that fits in 32 bits. */
static bool exchange_val(uint32_t value, size_t n, uint32_t power_up_us, uint32_t *page) {
    uint8_t tx[4] = {0};
    bits_put(tx, 0, value, n);
    return exchange(tx, n, power_up_us, page);
}

/* Cold-starts the tag and sends START_AUTH (11000) until it answers, up to
 * HT2_TRIES times in one powered session (a tag answers only every second
 * one). With need >= 2 the UID must come back the same twice (no CRC). The
 * last answered START_AUTH leaves the field on, the tag waiting for the
 * password/challenge. */
static bool hitag2_start_auth(uint32_t *uid, uint8_t need) {
    lf_rdr_field(false);
    bsp_delay_ms(HT2_RESET_MS);
    ht2_frame_reset(&m_frame);
    ht2_agree_t agree;
    ht2_agree_reset(&agree);
    for (uint8_t i = 0; i < HT2_TRIES; i++) {
        uint32_t v;
        if (!exchange_val(0x18u, 5, i == 0 ? HT2_POWER_UP_US : 0, &v)) {
            continue;
        }
        if (need < 2 || ht2_agree_add(&agree, v, uid)) {
            *uid = v;
            return true;
        }
    }
    return false;
}

bool hitag2_reader_get_uid(uint8_t uid[HITAG2_PAGE_SIZE], uint32_t timeout_ms) {
    (void)timeout_ms;
    uint32_t v;
    bool ok = hitag2_start_auth(&v, 2);
    lf_rdr_field(false);
    if (ok) {
        u32_be(v, uid);
    }
    return ok;
}

static uint8_t hitag2_crypto_read_session(const uint8_t key[HITAG2_KEY_SIZE],
                                uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                uint32_t timeout_ms) {
    (void)timeout_ms;
    memset(pages, 0, HITAG2_NUM_PAGES * HITAG2_PAGE_SIZE);

    uint32_t uid;
    if (!hitag2_start_auth(&uid, 2)) {
        lf_rdr_field(false);
        return HITAG2_FAIL_UID;
    }
    u32_be(uid, pages[HITAG2_PAGE_UID]);

    /* Key and UID: little-endian decodes of the raw bytes, bit-reversed per
     * byte (hitag2_rev64/32) -- matches proxmark3's hitag2_crypto(). IV 0:
     * Nr freshness only matters to an attacker, not a known-key read. */
    uint64_t key_raw = (uint64_t)key[0] | ((uint64_t)key[1] << 8) | ((uint64_t)key[2] << 16) |
                        ((uint64_t)key[3] << 24) | ((uint64_t)key[4] << 32) | ((uint64_t)key[5] << 40);
    uint64_t cs = hitag2_crypto_init(hitag2_rev64(key_raw), hitag2_rev32(le32(pages[HITAG2_PAGE_UID])), 0);

    uint8_t nrar[8];
    memset(nrar, 0x00, 4);           /* Nr */
    memset(nrar + 4, 0xFF, 4);
    hitag2_crypto_build_auth(&cs, nrar + 4);  /* Ar = inverted keystream, consumes 32 bits */

    uint32_t page3;
    if (!exchange(nrar, 64, 0, &page3)) {
        /* No answer: wrong key, or the tag is in password mode. */
        lf_rdr_field(false);
        return HITAG2_FAIL_AUTH;
    }
    uint8_t reply[4];
    u32_be(page3, reply);
    hitag2_crypto_transcrypt(&cs, reply, 4, 0);
    memcpy(pages[HITAG2_PAGE_CONFIG], reply, 4);  /* page 3 from the auth reply */

    static const uint8_t remaining_pages[] = {1, 2, 4, 5, 6, 7};
    for (size_t i = 0; i < sizeof(remaining_pages); i++) {
        uint8_t page = remaining_pages[i];
        uint16_t frame = hitag2_page_frame(HITAG2_READ_PAGE, page);
        /* Every frame is encrypted in crypto mode, command as much as reply:
         * pack the 10-bit frame into bytes as a received frame would be, XOR
         * the next keystream (1 byte + 2 bits), send the result. */
        uint8_t fb[2] = { (uint8_t)(frame >> 2), (uint8_t)((frame & 0x3u) << 6) };
        hitag2_crypto_transcrypt(&cs, fb, 1, 2);
        uint32_t enc_value = ((uint32_t)fb[0] << 2) | (fb[1] >> 6);

        uint32_t v;
        if (!exchange_val(enc_value, 10, 0, &v)) {
            lf_rdr_field(false);
            return HITAG2_FAIL_PAGE;
        }
        uint8_t out[4];
        u32_be(v, out);
        hitag2_crypto_transcrypt(&cs, out, 4, 0);
        memcpy(pages[page], out, 4);
    }
    lf_rdr_field(false);
    return HITAG2_FAIL_NONE;
}

/* Hitag2 replies carry no checksum, so a misread page is otherwise silent. A
 * session is repeated from a fresh power-up until one returns the same eight
 * pages as an earlier one (the last HITAG2_KEEP are kept). Crypto sessions
 * advance the cipher per command, so retry is whole-session, not per-page. */
#define HITAG2_SESSION_ATTEMPTS  12
#define HITAG2_FIELD_OFF_MS      10
#define HITAG2_KEEP              4

static uint8_t g_fail_stage;
static uint8_t g_attempts;

void hitag2_reader_last_result(uint8_t *fail_stage, uint8_t *attempts) {
    *fail_stage = g_fail_stage;
    *attempts = g_attempts;
}

typedef uint8_t (*hitag2_session_t)(const uint8_t *secret,
                                    uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                    uint32_t timeout_ms);

static bool hitag2_read_verified(hitag2_session_t session, const uint8_t *secret,
                                 uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                 uint32_t timeout_ms) {
    uint8_t prev[HITAG2_KEEP][HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE];
    uint8_t seen_uid[HITAG2_PAGE_SIZE] = {0};
    uint8_t n_prev = 0;

    g_fail_stage = HITAG2_FAIL_NONE;
    for (g_attempts = 1; g_attempts <= HITAG2_SESSION_ATTEMPTS; g_attempts++) {
        uint8_t stage = session(secret, pages, timeout_ms);
        if (stage == HITAG2_FAIL_NONE) {
            for (uint8_t i = 0; i < n_prev && i < HITAG2_KEEP; i++) {
                if (memcmp(prev[i], pages, sizeof(prev[i])) == 0) {
                    g_fail_stage = HITAG2_FAIL_NONE;
                    return true;
                }
            }
            memcpy(prev[n_prev % HITAG2_KEEP], pages, sizeof(prev[0]));
            n_prev++;
            stage = HITAG2_FAIL_VERIFY;
        }
        if (stage > HITAG2_FAIL_UID) {
            memcpy(seen_uid, pages[HITAG2_PAGE_UID], HITAG2_PAGE_SIZE);
        }
        if (stage > g_fail_stage) {
            g_fail_stage = stage;  /* report the furthest any attempt got */
        }
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    g_attempts = HITAG2_SESSION_ATTEMPTS;
    /* The next attempt wipes pages[]; hand back the last UID actually read. */
    memcpy(pages[HITAG2_PAGE_UID], seen_uid, HITAG2_PAGE_SIZE);
    return false;
}

/* Password mode has no CRC, so each page is read until two answers agree
 * (ht2_agree) rather than by repeating the whole session. START_AUTH is
 * retried within the one session; the field stays up throughout. */
bool hitag2_reader_read(const uint8_t password[HITAG2_PAGE_SIZE],
                         uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                         uint32_t timeout_ms) {
    (void)timeout_ms;
    g_fail_stage = HITAG2_FAIL_NONE;
    g_attempts = 1;
    memset(pages, 0, HITAG2_NUM_PAGES * HITAG2_PAGE_SIZE);

    uint32_t uid;
    if (!hitag2_start_auth(&uid, 2)) {
        lf_rdr_field(false);
        g_fail_stage = HITAG2_FAIL_UID;
        return false;
    }

    uint32_t pwd_val = ((uint32_t)password[0] << 24) | ((uint32_t)password[1] << 16) |
                       ((uint32_t)password[2] << 8)  | (uint32_t)password[3];
    uint32_t page3;
    bool authed = false;
    for (uint8_t i = 0; i < 3 && !authed; i++) {
        authed = exchange_val(pwd_val, 32, 0, &page3);
    }
    if (!authed) {
        /* Wrong password, or the tag is in crypto mode. */
        u32_be(uid, pages[HITAG2_PAGE_UID]);
        lf_rdr_field(false);
        g_fail_stage = HITAG2_FAIL_AUTH;
        return false;
    }

    uint8_t mask = 0;
    for (uint8_t p = 0; p < HITAG2_NUM_PAGES; p++) {
        uint16_t frame = hitag2_page_frame(HITAG2_READ_PAGE, p);
        ht2_agree_t agree;
        ht2_agree_reset(&agree);
        for (uint8_t i = 0; i < HT2_PAGE_TRIES; i++) {
            uint32_t v, agreed;
            if (exchange_val(frame, 10, 0, &v) && ht2_agree_add(&agree, v, &agreed)) {
                u32_be(agreed, pages[p]);
                mask |= (uint8_t)(1u << p);
                break;
            }
        }
    }
    lf_rdr_field(false);

    /* Page 0 read back must match the START_AUTH UID, or trust neither. */
    uint32_t page0 = ((uint32_t)pages[0][0] << 24) | ((uint32_t)pages[0][1] << 16) |
                     ((uint32_t)pages[0][2] << 8) | (uint32_t)pages[0][3];
    if ((mask & 1u) && page0 != uid) {
        mask &= (uint8_t)~1u;
    }
    if (mask != 0xFFu) {
        u32_be(uid, pages[HITAG2_PAGE_UID]);
        g_fail_stage = HITAG2_FAIL_PAGE;
        return false;
    }
    g_fail_stage = HITAG2_FAIL_NONE;
    return true;
}

bool hitag2_reader_crypto_read(const uint8_t key[HITAG2_KEY_SIZE],
                                uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                uint32_t timeout_ms) {
    return hitag2_read_verified(hitag2_crypto_read_session, key, pages, timeout_ms);
}

/* Debug: send START_AUTH and return the answer's envelope runs -- the ADC
 * decoder's own input -- as level+length bytes (bit 7 load level, bits 6..0
 * length in Tc, clamped to 0x7F). both_edges is accepted for CLI
 * compatibility and ignored; there are no rising-only edges on this path. */
bool hitag2_reader_raw_capture(uint8_t *intervals, uint8_t max_n, uint8_t *n_out,
                                uint32_t *rx_arm_gap_ticks_out, bool *hfclk_running_out,
                                bool both_edges, uint32_t timeout_ms) {
    (void)both_edges;
    (void)timeout_ms;
    *n_out = 0;
    *rx_arm_gap_ticks_out = 0;
    *hfclk_running_out = true;

    uint32_t uid;
    (void)hitag2_start_auth(&uid, 1);  /* retries internally; dump whatever the last try captured */
    lf_rdr_field(false);

    size_t nr = 0;
    const uint16_t *runs = lf_rdr_runs(&nr);
    uint8_t n = 0;
    for (size_t i = 0; i < nr && n < max_n; i++) {
        uint16_t len = LF_IA_RUN_LEN(runs[i]);
        intervals[n++] = (uint8_t)((LF_IA_RUN_IS_LOAD(runs[i]) ? 0x80 : 0) |
                                    (len > 0x7F ? 0x7F : len));
    }
    *n_out = n;
    return n > 0;
}
