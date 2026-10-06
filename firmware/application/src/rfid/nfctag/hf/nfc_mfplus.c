/**
 * @file nfc_mfplus.c
 * @brief MIFARE Plus SL3 (AES) emulation -- v1
 *
 * Scope: AuthenticateFirst, ReadBlock, WriteBlock, GetVersion. The card
 * starts already in SL3 (no SL0 personalization protocol) and does not
 * implement AuthenticateNonFirst. All sectors share one configurable AES
 * key for both Key A and Key B (real hardware has an independent key per
 * sector/keytype -- deliberate v1 simplification, noted in the header).
 *
 * Protocol bytes, session-key derivation, CMAC construction and the data
 * block IV scheme are taken from RRG proxmark3 (GPLv3): client/src/mifare/
 * mifare4.c (MifareAuth4, CalculateMAC, MFPReadBlock, MFPWriteBlock) and
 * client/src/cmdhfmfp.c (mfp_data_crypt -- the corrected IV construction;
 * mifare4.c itself has an older, explicitly-marked-wrong version left in
 * as a comment). Before writing this file, the full handshake and a MACed
 * + encrypted ReadBlock were round-tripped standalone in Python against
 * this exact algorithm to confirm both sides actually agree.
 */

#include <string.h>
#include "nfc_mfplus.h"
#include "nfc_14a_4.h"
#include "nfc_14a.h"
#include "tag_emulation.h"
#include "tag_persistence.h"
#include "fds_util.h"
#include "dfc_crypto.h"   // dfc_crypto_aes_cbc
#include "dfc_common.h"   // dfc_rotate_left
#include "aes_cmac.h"     // aes_cmac
#include "nrf_log.h"

#define MFPLUS_KEYSIZE 16

// ---- command bytes (see mifare4.c) ----
#define CMD_GETVERSION       0x60
#define CMD_GETVERSION_NEXT  0xAF
#define CMD_AUTH_FIRST_1     0x70
#define CMD_AUTH_FIRST_2     0x72
#define READ_BASE            0x31   // XOR 0x01=nomacres, 0x02=plain, 0x04=nomaccmd
#define WRITE_BASE           0xA1   // XOR 0x01=nomacres, 0x02=plain
#define STATUS_OK            0x90
#define STATUS_AUTH_ERR      0x00
#define STATUS_MAC_ERR       0x08
#define STATUS_BLOCK_ERR     0x09
#define STATUS_LEN_ERR       0x0C

typedef struct {
    bool     authenticated;
    uint8_t  RndA[16];
    uint8_t  RndB[16];
    uint8_t  TI[4];
    uint8_t  Kenc[16];
    uint8_t  Kmac[16];
    uint16_t R_Ctr;
    uint16_t W_Ctr;
    uint8_t  auth_pending_cmd[4];   // stashed phase-1 state
}
mfplus_session_t;

static nfc_tag_mfplus_information_t *m_tag_information = NULL;
static nfc_tag_14a_coll_res_reference_t m_shadow_coll_res;
static nfc_tag_14a_4_tcl_state_t m_tcl_session_state;
static mfplus_session_t m_sess;

nfc_tag_14a_coll_res_reference_t *nfc_tag_mfplus_get_coll_res(void) {
    if (m_tag_information == NULL) return NULL;
    m_shadow_coll_res.sak  = m_tag_information->res_coll.sak;
    m_shadow_coll_res.atqa = m_tag_information->res_coll.atqa;
    m_shadow_coll_res.uid  = m_tag_information->res_coll.uid;
    m_shadow_coll_res.size = &m_tag_information->res_coll.size;
    m_shadow_coll_res.ats  = &m_tag_information->res_coll.ats;
    return &m_shadow_coll_res;
}

static void session_reset(void) {
    memset(&m_sess, 0, sizeof(m_sess));
}

static void respond(uint16_t data_len, uint8_t status) {
    m_tcl_session_state.m_resp_buf[0] = status;
    if (data_len) {
        // caller already placed the (data_len-1) payload bytes at resp_buf[1..]
    }
    m_tcl_session_state.m_resp_len = data_len;
    m_tcl_session_state.m_response_ready = true;
    nfc_tag_14a_4_base_respond(&m_tcl_session_state);
}

static inline void respond_status(uint8_t status) {
    respond(1, status);
}

// ---- GetVersion: 3-frame DESFire-style response, hardware type bytes are
// MIFARE Plus family markers per AN10833 (0x2X); exact sub-byte values are
// for identification only, not verified against real MIFARE Plus silicon. ----
static void do_getversion_frame1(void) {
    uint8_t *r = m_tcl_session_state.m_resp_buf;
    r[1] = 0x04;  // vendor ID: NXP
    r[2] = 0x20;  // hardware type: MIFARE Plus family (AN10833, 0x2X)
    r[3] = 0x11;  // hardware subtype
    r[4] = 0x01;  // major version
    r[5] = 0x00;  // minor version
    r[6] = (m_tag_information->block_max == 256) ? 0x18 : 0x16; // storage size code
    r[7] = 0x05;  // protocol type: ISO14443-4 compliant
    respond(8, CMD_GETVERSION_NEXT);
}

static void do_getversion_frame2(void) {
    uint8_t *r = m_tcl_session_state.m_resp_buf;
    r[1] = 0x04;
    r[2] = 0x20;
    r[3] = 0x11;
    r[4] = 0x01;
    r[5] = 0x00;
    r[6] = (m_tag_information->block_max == 256) ? 0x18 : 0x16;
    r[7] = 0x05;
    respond(8, CMD_GETVERSION_NEXT);
}

static void do_getversion_frame3(void) {
    uint8_t *r = m_tcl_session_state.m_resp_buf;
    memcpy(&r[1], m_tag_information->res_coll.uid, 7);
    memset(&r[8], 0, 5);   // batch number
    r[13] = 0x01;          // fab week
    r[14] = 0x24;          // fab year
    respond(15, STATUS_OK);
}

// ---- AuthenticateFirst ----
static void do_auth1(uint8_t *apdu, uint16_t len) {
    if (len != 4) { respond_status(STATUS_LEN_ERR); return; }
    session_reset();

    uint8_t RndB[16];
    // Software rand(), seeded once at boot from the hardware RNG -- same
    // approach nfc_mf1.c's "HARD" nonce mode already uses synchronously
    // during live field exchanges (see nfc_tag_mf1_random_nonce()).
    for (int i = 0; i < 16; i++) RndB[i] = (uint8_t)rand();

    uint8_t iv0[16] = {0};
    uint8_t enc[16];
    dfc_crypto_aes_cbc(true, m_tag_information->default_key, MFPLUS_KEYSIZE, iv0, RndB, enc, 16);

    memcpy(m_sess.RndB, RndB, 16);
    memcpy(&m_tcl_session_state.m_resp_buf[1], enc, 16);
    respond(17, STATUS_OK);
}

static void do_auth2(uint8_t *apdu, uint16_t len) {
    if (len != 33) { respond_status(STATUS_LEN_ERR); return; }

    uint8_t iv0[16] = {0};
    uint8_t raw[32];
    dfc_crypto_aes_cbc(false, m_tag_information->default_key, MFPLUS_KEYSIZE, iv0, &apdu[1], raw, 32);

    uint8_t RndA[16];
    memcpy(RndA, &raw[0], 16);
    uint8_t RndBp_recv[16];
    memcpy(RndBp_recv, &raw[16], 16);

    uint8_t RndBp_expect[16];
    memcpy(RndBp_expect, m_sess.RndB, 16);
    dfc_rotate_left(RndBp_expect, 16);

    if (memcmp(RndBp_recv, RndBp_expect, 16) != 0) {
        session_reset();
        respond_status(STATUS_AUTH_ERR);
        return;
    }

    uint8_t TI[4];
    for (int i = 0; i < 4; i++) TI[i] = (uint8_t)rand();

    uint8_t RndAp[16];
    memcpy(RndAp, RndA, 16);
    dfc_rotate_left(RndAp, 16);

    uint8_t plain[32];
    memcpy(&plain[0], TI, 4);
    memcpy(&plain[4], RndAp, 16);
    memset(&plain[20], 0, 6);  // PICCap2: no extended capabilities
    memset(&plain[26], 0, 6);  // PCDCap2: echo (PCD sent none)

    uint8_t iv0b[16] = {0};
    uint8_t enc[32];
    dfc_crypto_aes_cbc(true, m_tag_information->default_key, MFPLUS_KEYSIZE, iv0b, plain, enc, 32);

    // Session key derivation (RndA/RndB as sent by the reader, matching
    // mifare4.c MifareAuth4's kenc/kmac construction).
    uint8_t kenc_in[16], kmac_in[16];
    memcpy(&kenc_in[0], &RndA[11], 5);
    memcpy(&kenc_in[5], &m_sess.RndB[11], 5);
    for (int i = 0; i < 5; i++) kenc_in[10 + i] = RndA[4 + i] ^ m_sess.RndB[4 + i];
    kenc_in[15] = 0x11;

    memcpy(&kmac_in[0], &RndA[7], 5);
    memcpy(&kmac_in[5], &m_sess.RndB[7], 5);
    for (int i = 0; i < 5; i++) kmac_in[10 + i] = RndA[0 + i] ^ m_sess.RndB[0 + i];
    kmac_in[15] = 0x22;

    uint8_t iv0c[16] = {0}, iv0d[16] = {0};
    dfc_crypto_aes_cbc(true, m_tag_information->default_key, MFPLUS_KEYSIZE, iv0c, kenc_in, m_sess.Kenc, 16);
    dfc_crypto_aes_cbc(true, m_tag_information->default_key, MFPLUS_KEYSIZE, iv0d, kmac_in, m_sess.Kmac, 16);

    memcpy(m_sess.RndA, RndA, 16);
    memcpy(m_sess.TI, TI, 4);
    m_sess.R_Ctr = 0;
    m_sess.W_Ctr = 0;
    m_sess.authenticated = true;

    memcpy(&m_tcl_session_state.m_resp_buf[1], enc, 32);
    respond(33, STATUS_OK);
}

// ---- CMAC (8-byte truncated AES-CMAC with Kmac), matching CalculateMAC ----
static void calc_mac(uint8_t cmd_or_status, uint16_t ctr, uint8_t block_num,
                      uint8_t block_count, const uint8_t *extra, uint16_t extra_len,
                      bool is_resp, bool is_write, uint8_t *mac_out) {
    uint8_t md[64];
    uint16_t n = 0;
    md[n++] = cmd_or_status;
    md[n++] = (uint8_t)(ctr & 0xFF);
    md[n++] = (uint8_t)(ctr >> 8);
    memcpy(&md[n], m_sess.TI, 4);
    n += 4;
    if (is_resp && !is_write) {
        md[n++] = block_num;
        md[n++] = 0;
        md[n++] = block_count;
    }
    if (!(is_resp && is_write)) {
        memcpy(&md[n], extra, extra_len);
        n += extra_len;
    }
    aes_cmac(m_sess.Kmac, 16, md, n, mac_out);  // mac_out gets 16 bytes; caller uses first 8
}

// ---- ReadBlock ----
static void do_read(uint8_t *apdu, uint16_t len) {
    if (!m_sess.authenticated) { respond_status(STATUS_AUTH_ERR); return; }
    if ((apdu[0] & 0xF8) != 0x30) { respond_status(STATUS_LEN_ERR); return; }

    uint8_t diff = apdu[0] ^ READ_BASE;
    bool nomacres  = diff & 0x01;
    bool plain     = diff & 0x02;
    bool nomaccmd  = diff & 0x04;

    uint16_t need = nomaccmd ? 4 : 12;
    if (len != need) { respond_status(STATUS_LEN_ERR); return; }

    uint8_t block_num   = apdu[1];
    uint8_t block_count = apdu[3];

    if (!nomaccmd) {
        uint8_t mac[16];
        calc_mac(apdu[0], m_sess.R_Ctr, block_num, block_count, &apdu[1], 3, false, false, mac);
        if (memcmp(mac, &apdu[4], 8) != 0) { respond_status(STATUS_MAC_ERR); return; }
    }

    if (block_count == 0 || (uint32_t)block_num + block_count > m_tag_information->block_max) {
        respond_status(STATUS_BLOCK_ERR);
        return;
    }

    uint8_t plaintext[16 * 4]; // v1 caps a single transfer at 4 blocks (64 bytes)
    if (block_count > 4) { respond_status(STATUS_LEN_ERR); return; }
    memcpy(plaintext, m_tag_information->memory[block_num], 16u * block_count);

    // Reference (mifare4.c MFPReadBlock) increments R_Ctr BEFORE computing
    // the response MAC -- and mfpReadSector only decrypts the response
    // *after* MFPReadBlock returns (i.e. after that increment), so the
    // reader decrypts with the POST-increment counter. The card's encrypt
    // IV and response MAC must both use the same post-increment value, so
    // the increment happens here, before either.
    m_sess.R_Ctr++;

    uint8_t *out = &m_tcl_session_state.m_resp_buf[1];
    if (plain) {
        memcpy(out, plaintext, 16u * block_count);
    } else {
        uint8_t iv[16] = {0};
        uint8_t ctr_lo = (uint8_t)(m_sess.R_Ctr & 0xFF);
        iv[0] = ctr_lo; iv[4] = ctr_lo; iv[8] = ctr_lo;
        memcpy(&iv[12], m_sess.TI, 4);
        dfc_crypto_aes_cbc(true, m_sess.Kenc, 16, iv, plaintext, out, 16u * block_count);
    }

    uint16_t resp_data_len = 16u * block_count;
    uint16_t total = 1 + resp_data_len;

    if (!nomacres) {
        uint8_t status_and_data[1 + 16 * 4];
        status_and_data[0] = STATUS_OK;
        memcpy(&status_and_data[1], out, resp_data_len);
        uint8_t mac[16];
        calc_mac(STATUS_OK, m_sess.R_Ctr, block_num, block_count, &status_and_data[1], resp_data_len, true, false, mac);
        memcpy(&m_tcl_session_state.m_resp_buf[total], mac, 8);
        total += 8;
    }

    respond(total, STATUS_OK);
}

// ---- WriteBlock ----
static void do_write(uint8_t *apdu, uint16_t len) {
    if (!m_sess.authenticated) { respond_status(STATUS_AUTH_ERR); return; }
    if ((apdu[0] & 0xFC) != 0xA0) { respond_status(STATUS_LEN_ERR); return; }

    uint8_t diff = apdu[0] ^ WRITE_BASE;
    bool nomacres = diff & 0x01;
    bool plain    = diff & 0x02;

    if (len != 1 + 2 + 16 + 8) { respond_status(STATUS_LEN_ERR); return; }

    uint8_t block_num = apdu[1];
    // apdu[2] = block header, unused in v1 (no value-block semantics)

    if (block_num >= m_tag_information->block_max) { respond_status(STATUS_BLOCK_ERR); return; }

    uint8_t mac[16];
    calc_mac(apdu[0], m_sess.W_Ctr, block_num, 1, &apdu[1], 18, false, true, mac);
    if (memcmp(mac, &apdu[19], 8) != 0) { respond_status(STATUS_MAC_ERR); return; }

    uint8_t plaintext[16];
    if (plain) {
        memcpy(plaintext, &apdu[3], 16);
    } else {
        uint8_t iv[16] = {0};
        uint8_t ctr_lo = (uint8_t)(m_sess.W_Ctr & 0xFF);
        iv[3] = ctr_lo; iv[7] = ctr_lo; iv[11] = ctr_lo; iv[15] = ctr_lo;
        memcpy(&iv[0], m_sess.TI, 4);
        dfc_crypto_aes_cbc(false, m_sess.Kenc, 16, iv, &apdu[3], plaintext, 16);
    }
    memcpy(m_tag_information->memory[block_num], plaintext, 16);

    m_sess.W_Ctr++;

    uint16_t total = 1;
    if (!nomacres) {
        uint8_t status_mac[16];
        calc_mac(STATUS_OK, m_sess.W_Ctr, block_num, 1, NULL, 0, true, true, status_mac);
        memcpy(&m_tcl_session_state.m_resp_buf[1], status_mac, 8);
        total += 8;
    }
    respond(total, STATUS_OK);
}

static void nfc_tag_mfplus_state_handler(uint8_t *data, uint16_t szBytes) {
    if (!nfc_tag_14a_4_base_handler(&m_tcl_session_state, data, szBytes)) return;

    uint8_t *apdu = m_tcl_session_state.m_apdu_buf;
    uint16_t len = m_tcl_session_state.m_apdu_len;
    m_tcl_session_state.m_resp_len = 0;

    if (len < 1) { respond_status(STATUS_LEN_ERR); return; }

    switch (apdu[0]) {
        case CMD_GETVERSION:      do_getversion_frame1(); break;
        case CMD_GETVERSION_NEXT: {
            static uint8_t gv_frame = 0;
            gv_frame++;
            if (gv_frame == 1) do_getversion_frame2();
            else { do_getversion_frame3(); gv_frame = 0; }
            break;
        }
        case CMD_AUTH_FIRST_1: do_auth1(apdu, len); break;
        case CMD_AUTH_FIRST_2: do_auth2(apdu, len); break;
        default:
            if ((apdu[0] & 0xF8) == 0x30) do_read(apdu, len);
            else if ((apdu[0] & 0xFC) == 0xA0) do_write(apdu, len);
            else respond_status(STATUS_LEN_ERR);
            break;
    }
}

static void nfc_tag_mfplus_reset_handler(void) {
    nfc_tag_14a_4_reset_state(&m_tcl_session_state);
    session_reset();
}

int nfc_tag_mfplus_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    if (buffer->length < sizeof(nfc_tag_mfplus_information_t)) {
        NRF_LOG_ERROR("MFPlus loadcb: buffer too small");
        return 0;
    }
    m_tag_information = (nfc_tag_mfplus_information_t *)buffer->buffer;
    session_reset();

    nfc_tag_14a_handler_t handler = {
        .get_coll_res = nfc_tag_mfplus_get_coll_res,
        .cb_state     = nfc_tag_mfplus_state_handler,
        .cb_reset     = nfc_tag_mfplus_reset_handler,
    };
    nfc_tag_14a_set_handler(&handler);
    return sizeof(nfc_tag_mfplus_information_t);
}

int nfc_tag_mfplus_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    if (m_tag_information == NULL) return 0;
    return sizeof(nfc_tag_mfplus_information_t);
}

bool nfc_tag_mfplus_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    if (tag_type != TAG_TYPE_MIFARE_PLUS_S2K_SL3 && tag_type != TAG_TYPE_MIFARE_PLUS_S4K_SL3) {
        return false;
    }

    tag_data_buffer_t *buffer = get_buffer_by_tag_type(tag_type);
    if (buffer == NULL || buffer->length < sizeof(nfc_tag_mfplus_information_t)) {
        NRF_LOG_ERROR("MFPlus factory: no buffer for slot %d", slot);
        return false;
    }
    nfc_tag_mfplus_information_t *info = (nfc_tag_mfplus_information_t *)buffer->buffer;
    memset(info, 0, sizeof(*info));

    info->res_coll.size    = NFC_TAG_14A_UID_DOUBLE_SIZE;
    info->res_coll.atqa[0] = 0x44;
    info->res_coll.atqa[1] = 0x00;
    info->res_coll.sak[0]  = 0x20;  // full ISO14443-4, SL3
    static const uint8_t default_uid[] = {0x04, 0x4D, 0x50, 0x33, 0x53, 0x4C, 0x33};
    memcpy(info->res_coll.uid, default_uid, 7);

    static const uint8_t default_ats[] = {0x05, 0x78, 0x80, 0x90, 0x02};
    info->res_coll.ats.length = sizeof(default_ats);
    memcpy(info->res_coll.ats.data, default_ats, sizeof(default_ats));

    info->block_max = (tag_type == TAG_TYPE_MIFARE_PLUS_S4K_SL3) ? 256 : 128;
    memset(info->default_key, 0x00, 16);  // all-zero transport key, like SL0->SL3 default

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(*info), info);
    NRF_LOG_INFO("MIFARE Plus SL3 factory slot %d: %s", slot, ret ? "OK" : "FAIL");
    return ret;
}
