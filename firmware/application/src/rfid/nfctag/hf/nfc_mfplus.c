/**
 * @file nfc_mfplus.c
 * @brief MIFARE Plus SL0/SL3 (AES) emulation -- v2
 *
 * Scope: WritePerso/CommitPerso (SL0 personalization, SL0->SL3 only, no
 * SL1 leg), AuthenticateFirst, AuthenticateNonFirst, ReadBlock/WriteBlock,
 * GetVersion. Per-sector Key A/B plus CardMasterKey (0x9000), CardConfigKey
 * (0x9001) and L3SwitchKey (0x9003) are stored and enforced. Other
 * WritePerso addresses RRG proxmark3's `hf mfp initp` writes (0x9002,
 * 0x9004, 0x9006, 0x9007, 0xA000, 0xA001, 0xA080, 0xA081, 0xC000, 0xC001,
 * 0xB000-0xB003) are accepted (ack'd) so that command completes, but not
 * stored or interpreted -- their behaviour is in NXP's confidential MIFARE
 * Plus functional spec, not the public datasheet.
 *
 * Protocol bytes, session-key derivation, CMAC construction and the data
 * block IV scheme are taken from RRG proxmark3 (GPLv3): client/src/mifare/
 * mifare4.c (MifareAuth4, MFPWritePerso, MFPCommitPerso, CalculateMAC,
 * MFPReadBlock, MFPWriteBlock) and client/src/cmdhfmfp.c (mfp_data_crypt --
 * the corrected IV construction; mifare4.c itself has an older, explicitly
 * marked-wrong version left in as a comment). The AuthenticateNonFirst IV
 * construction mirrors mifare4.c's own nonfirst branch verbatim, including
 * proxmark3's own comment that it isn't confirmed against the confidential
 * datasheet -- this keeps the firmware interoperable with proxmark3 as a
 * reader, which is the only independently checkable reference available.
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
#define CMD_AUTH_NONFIRST_1  0x76
#define CMD_AUTH_2           0x72
#define CMD_WRITEPERSO       0xA8
#define CMD_COMMITPERSO      0xAA
#define READ_BASE            0x31   // XOR 0x01=nomacres, 0x02=plain, 0x04=nomaccmd
#define WRITE_BASE           0xA1   // XOR 0x01=nomacres, 0x02=plain
#define STATUS_OK            0x90
#define STATUS_AUTH_ERR      0x00
#define STATUS_MAC_ERR       0x08
#define STATUS_BLOCK_ERR     0x09
#define STATUS_NOT_AVAIL     0x0B
#define STATUS_LEN_ERR       0x0C
#define STATUS_GENERAL_ERR   0x0F

typedef struct {
    bool     authenticated;
    uint8_t  RndA[16];
    uint8_t  RndB[16];
    uint8_t  TI[4];
    uint8_t  Kenc[16];
    uint8_t  Kmac[16];
    uint16_t R_Ctr;
    uint16_t W_Ctr;
    bool     nonfirst_pending;
    uint8_t  nonfirst_key[16];   // key being switched to, stashed between the two auth phases
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

// 8-byte CMAC used on the wire is bytes 1,3,5,...,15 of the full 16-byte
// AES-CMAC -- see proxmark3 crypto/libpcrypto.c aes_cmac8(). Taking the
// first 8 bytes instead (as a naive truncation would) does not interop
// with proxmark3 or real MIFARE Plus.
static void cmac_truncate8(const uint8_t *full16, uint8_t *out8) {
    for (int i = 0; i < 8; i++) out8[i] = full16[2 * i + 1];
}

// ---- key lookup -----------------------------------------------------
// key_num wire encoding: apdu low byte = key_num low byte, apdu high byte
// = key_num high byte (matches proxmark3's keyNum[1]/keyNum[0] split).
// Returns NULL for an address this emulation doesn't enforce.
static uint8_t *lookup_key(uint16_t key_num) {
    uint8_t hi = (uint8_t)(key_num >> 8);
    uint8_t lo = (uint8_t)key_num;
    if (hi == 0x40) {
        uint8_t sector  = lo / 2;
        uint8_t keytype = lo % 2;
        if (sector >= m_tag_information->num_sectors) return NULL;
        return m_tag_information->sector_keys[sector][keytype];
    }
    if (hi == 0x90) {
        switch (lo) {
            case 0x00: return m_tag_information->master_key;
            case 0x01: return m_tag_information->config_key;
            case 0x03: return m_tag_information->l3_switch_key;
            default: return NULL;
        }
    }
    return NULL;
}

// ---- management API, shared by the wire WritePerso/CommitPerso handlers
// (do_writeperso/do_commitperso) and the host-side debug/config commands
// in app_cmd.c. Callers there are responsible for the SL0-only gate and
// APDU length checks the wire path also enforces. ----
uint8_t nfc_tag_mfplus_write_perso(uint8_t addr_hi, uint8_t addr_lo, const uint8_t *key) {
    if (m_tag_information == NULL) return STATUS_GENERAL_ERR;
    uint8_t hi = addr_hi, lo = addr_lo;

    if (hi == 0x40) {
        uint8_t sector  = lo / 2;
        uint8_t keytype = lo % 2;
        if (sector >= m_tag_information->num_sectors) return STATUS_BLOCK_ERR;
        memcpy(m_tag_information->sector_keys[sector][keytype], key, 16);
        return STATUS_OK;
    }
    if (hi == 0x90) {
        switch (lo) {
            case 0x00: memcpy(m_tag_information->master_key, key, 16); m_tag_information->master_key_written = 1; return STATUS_OK;
            case 0x01: memcpy(m_tag_information->config_key, key, 16); m_tag_information->config_key_written = 1; return STATUS_OK;
            case 0x03: memcpy(m_tag_information->l3_switch_key, key, 16); m_tag_information->l3_switch_key_written = 1; return STATUS_OK;
            case 0x02: case 0x04: case 0x06: case 0x07: return STATUS_OK;  // accepted, not stored
            default: return STATUS_BLOCK_ERR;
        }
    }
    if (hi == 0xA0 && (lo == 0x00 || lo == 0x01 || lo == 0x80 || lo == 0x81)) return STATUS_OK;
    if (hi == 0xC0 && (lo == 0x00 || lo == 0x01)) return STATUS_OK;
    if (hi == 0xB0 && lo <= 0x03) return STATUS_OK;  // config blocks accepted, not interpreted

    return STATUS_BLOCK_ERR;
}

uint8_t nfc_tag_mfplus_commit_perso(void) {
    if (m_tag_information == NULL) return STATUS_GENERAL_ERR;
    if (m_tag_information->level != MFPLUS_LEVEL_SL0) return STATUS_NOT_AVAIL;
    if (!m_tag_information->master_key_written || !m_tag_information->config_key_written ||
            !m_tag_information->l3_switch_key_written) {
        return STATUS_GENERAL_ERR;
    }
    m_tag_information->level = MFPLUS_LEVEL_SL3;
    session_reset();
    return STATUS_OK;
}

void nfc_tag_mfplus_get_status(uint8_t *level, uint16_t *block_max) {
    *level = (m_tag_information != NULL) ? m_tag_information->level : 0;
    *block_max = (m_tag_information != NULL) ? m_tag_information->block_max : 0;
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

// ---- WritePerso / CommitPerso (SL0 only) -----------------------------
static void do_writeperso(uint8_t *apdu, uint16_t len) {
    if (m_tag_information->level != MFPLUS_LEVEL_SL0) { respond_status(STATUS_NOT_AVAIL); return; }
    if (len != 19) { respond_status(STATUS_LEN_ERR); return; }

    respond_status(nfc_tag_mfplus_write_perso(apdu[2], apdu[1], &apdu[3]));
}

static void do_commitperso(uint16_t len) {
    if (len != 1) { respond_status(STATUS_LEN_ERR); return; }
    respond_status(nfc_tag_mfplus_commit_perso());
}

// ---- AuthenticateFirst / AuthenticateNonFirst ----
static void do_auth1(uint8_t *apdu, uint16_t len) {
    bool nonfirst = (apdu[0] == CMD_AUTH_NONFIRST_1);
    if (nonfirst) {
        if (len != 3) { respond_status(STATUS_LEN_ERR); return; }
        if (!m_sess.authenticated) { respond_status(STATUS_AUTH_ERR); return; }
    } else {
        if (len != 4) { respond_status(STATUS_LEN_ERR); return; }
        session_reset();
    }

    if (m_tag_information->level != MFPLUS_LEVEL_SL3) { respond_status(STATUS_NOT_AVAIL); return; }

    uint16_t key_num = ((uint16_t)apdu[2] << 8) | apdu[1];
    uint8_t *key = lookup_key(key_num);
    if (key == NULL) { respond_status(STATUS_BLOCK_ERR); return; }

    uint8_t RndB[16];
    // Software rand(), seeded once at boot from the hardware RNG -- same
    // approach nfc_mf1.c's "HARD" nonce mode already uses synchronously
    // during live field exchanges (see nfc_tag_mf1_random_nonce()).
    for (int i = 0; i < 16; i++) RndB[i] = (uint8_t)rand();

    // Stash the key for do_auth2, which gets no key number of its own on
    // the wire (0x72 carries only the encrypted nonce exchange).
    memcpy(m_sess.nonfirst_key, key, 16);
    m_sess.nonfirst_pending = nonfirst;

    uint8_t enc[16];
    if (nonfirst) {
        uint8_t ivr[16];
        uint8_t r_lo = (uint8_t)(m_sess.R_Ctr & 0xFF), r_hi = (uint8_t)(m_sess.R_Ctr >> 8);
        uint8_t w_lo = (uint8_t)(m_sess.W_Ctr & 0xFF), w_hi = (uint8_t)(m_sess.W_Ctr >> 8);
        ivr[0] = r_lo; ivr[1] = r_hi; ivr[2] = w_lo; ivr[3] = w_hi;
        ivr[4] = r_lo; ivr[5] = r_hi; ivr[6] = w_lo; ivr[7] = w_hi;
        ivr[8] = r_lo; ivr[9] = r_hi; ivr[10] = w_lo; ivr[11] = w_hi;
        memcpy(&ivr[12], m_sess.TI, 4);
        dfc_crypto_aes_cbc(true, key, MFPLUS_KEYSIZE, ivr, RndB, enc, 16);
    } else {
        uint8_t iv0[16] = {0};
        dfc_crypto_aes_cbc(true, key, MFPLUS_KEYSIZE, iv0, RndB, enc, 16);
    }

    memcpy(m_sess.RndB, RndB, 16);
    memcpy(&m_tcl_session_state.m_resp_buf[1], enc, 16);
    respond(17, STATUS_OK);
}

static void do_auth2(uint8_t *apdu, uint16_t len) {
    if (len != 33) { respond_status(STATUS_LEN_ERR); return; }
    bool nonfirst = m_sess.nonfirst_pending;
    const uint8_t *key = m_sess.nonfirst_key;  // stashed by do_auth1, either case

    uint8_t raw[32];
    if (nonfirst) {
        uint8_t ivw[16];
        uint8_t r_lo = (uint8_t)(m_sess.R_Ctr & 0xFF), r_hi = (uint8_t)(m_sess.R_Ctr >> 8);
        uint8_t w_lo = (uint8_t)(m_sess.W_Ctr & 0xFF), w_hi = (uint8_t)(m_sess.W_Ctr >> 8);
        ivw[0] = r_lo; ivw[1] = r_hi; ivw[2] = w_lo; ivw[3] = w_hi;
        ivw[4] = r_lo; ivw[5] = r_hi; ivw[6] = w_lo; ivw[7] = w_hi;
        ivw[8] = r_lo; ivw[9] = r_hi; ivw[10] = w_lo; ivw[11] = w_hi;
        ivw[12] = r_lo; ivw[13] = r_hi; ivw[14] = w_lo; ivw[15] = w_hi;
        memcpy(ivw, m_sess.TI, 4);  // overwrites bytes 0..3, matches mifare4.c
        dfc_crypto_aes_cbc(false, key, MFPLUS_KEYSIZE, ivw, &apdu[1], raw, 32);
    } else {
        uint8_t iv0[16] = {0};
        dfc_crypto_aes_cbc(false, key, MFPLUS_KEYSIZE, iv0, &apdu[1], raw, 32);
    }

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

    uint8_t RndAp[16];
    memcpy(RndAp, RndA, 16);
    dfc_rotate_left(RndAp, 16);

    uint8_t kenc_in[16], kmac_in[16];
    memcpy(&kenc_in[0], &RndA[11], 5);
    memcpy(&kenc_in[5], &m_sess.RndB[11], 5);
    for (int i = 0; i < 5; i++) kenc_in[10 + i] = RndA[4 + i] ^ m_sess.RndB[4 + i];
    kenc_in[15] = 0x11;

    memcpy(&kmac_in[0], &RndA[7], 5);
    memcpy(&kmac_in[5], &m_sess.RndB[7], 5);
    for (int i = 0; i < 5; i++) kmac_in[10 + i] = RndA[0 + i] ^ m_sess.RndB[0 + i];
    kmac_in[15] = 0x22;

    uint8_t Kenc[16], Kmac[16];
    uint8_t iv0c[16] = {0}, iv0d[16] = {0};
    dfc_crypto_aes_cbc(true, key, MFPLUS_KEYSIZE, iv0c, kenc_in, Kenc, 16);
    dfc_crypto_aes_cbc(true, key, MFPLUS_KEYSIZE, iv0d, kmac_in, Kmac, 16);
    memcpy(m_sess.Kenc, Kenc, 16);
    memcpy(m_sess.Kmac, Kmac, 16);
    memcpy(m_sess.RndA, RndA, 16);

    if (nonfirst) {
        // TI, R_Ctr, W_Ctr carry over from the session this nonfirst auth
        // was issued in.
        uint8_t ivr[16];
        uint8_t r_lo = (uint8_t)(m_sess.R_Ctr & 0xFF), r_hi = (uint8_t)(m_sess.R_Ctr >> 8);
        uint8_t w_lo = (uint8_t)(m_sess.W_Ctr & 0xFF), w_hi = (uint8_t)(m_sess.W_Ctr >> 8);
        ivr[0] = r_lo; ivr[1] = r_hi; ivr[2] = w_lo; ivr[3] = w_hi;
        ivr[4] = r_lo; ivr[5] = r_hi; ivr[6] = w_lo; ivr[7] = w_hi;
        ivr[8] = r_lo; ivr[9] = r_hi; ivr[10] = w_lo; ivr[11] = w_hi;
        memcpy(&ivr[12], m_sess.TI, 4);
        uint8_t enc[16];
        dfc_crypto_aes_cbc(true, key, MFPLUS_KEYSIZE, ivr, RndAp, enc, 16);
        memcpy(&m_tcl_session_state.m_resp_buf[1], enc, 16);
        m_sess.authenticated = true;
        m_sess.nonfirst_pending = false;
        respond(17, STATUS_OK);
        return;
    }

    uint8_t TI[4];
    for (int i = 0; i < 4; i++) TI[i] = (uint8_t)rand();
    memcpy(m_sess.TI, TI, 4);

    uint8_t plain[32];
    memcpy(&plain[0], TI, 4);
    memcpy(&plain[4], RndAp, 16);
    memset(&plain[20], 0, 6);  // PICCap2: no extended capabilities
    memset(&plain[26], 0, 6);  // PCDCap2: echo (PCD sent none)

    uint8_t iv0b[16] = {0};
    uint8_t enc[32];
    dfc_crypto_aes_cbc(true, key, MFPLUS_KEYSIZE, iv0b, plain, enc, 32);

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
    uint8_t md[96];  // worst case: 1+2+4+3+64(4 blocks) = 74
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
    uint8_t full[16];
    aes_cmac(m_sess.Kmac, 16, md, n, full);
    cmac_truncate8(full, mac_out);
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
        uint8_t mac[8];
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
        uint8_t mac[8];
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

    uint8_t mac[8];
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
        uint8_t status_mac[8];
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
        case CMD_WRITEPERSO:   do_writeperso(apdu, len); break;
        case CMD_COMMITPERSO:  do_commitperso(len); break;
        case CMD_AUTH_FIRST_1:
        case CMD_AUTH_NONFIRST_1: do_auth1(apdu, len); break;
        case CMD_AUTH_2: do_auth2(apdu, len); break;
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
    info->res_coll.sak[0]  = 0x20;  // full ISO14443-4, SL0/SL3
    static const uint8_t default_uid[] = {0x04, 0x4D, 0x50, 0x33, 0x53, 0x4C, 0x33};
    memcpy(info->res_coll.uid, default_uid, 7);

    static const uint8_t default_ats[] = {0x05, 0x78, 0x80, 0x90, 0x02};
    info->res_coll.ats.length = sizeof(default_ats);
    memcpy(info->res_coll.ats.data, default_ats, sizeof(default_ats));

    bool is_4k = (tag_type == TAG_TYPE_MIFARE_PLUS_S4K_SL3);
    info->block_max   = is_4k ? 256 : 128;
    info->num_sectors = is_4k ? 40 : 32;
    // Starts in SL0 (factory/transport state); `hf mfplus wrp`/`initp` then
    // `commitp` personalizes it and switches it to SL3. All keys start
    // zeroed, matching the real card's SL0 default transport key.

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(*info), info);
    NRF_LOG_INFO("MIFARE Plus SL0 factory slot %d: %s", slot, ret ? "OK" : "FAIL");
    return ret;
}
