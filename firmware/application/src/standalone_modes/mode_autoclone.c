/*
 * mode_autoclone.c
 *
 * Two-step auto-sensing clone. Ultra only. Auto-detects the source frequency:
 *   HF 14A -> gen1a magic card, or LF EM410x -> T5577.
 *   1st ACTION: scan source, build block 0 from the anticollision (UID clone,
 *                   no key), and read any data sectors whose key is in the dict.
 *   2nd ACTION: write the buffered blocks to the magic card now present.
 * Optionally also clones the source into the active slot (cfg.also_slot).
 *
 * The UID is always cloned (works on UID-only / non-FF cards); data sectors are
 * cloned only where a key is found, so unknown-key sectors are left untouched.
 *
 * writes_tag + writes_slot -> requires STANDALONE_FLAG_HOST_OPTED_IN to arm.
 */

#include "app_standalone.h"
#include "standalone_led.h"

#if defined(PROJECT_CHAMELEON_ULTRA)

#include <string.h>

#include "nrf_log.h"
#include "app_status.h"
#include "rc522.h"
#include "rfid_main.h"
#include "bsp_delay.h"
#include "bsp_wdt.h"
#include "tag_emulation.h"
#include "tag_base_type.h"
#include "nfc_14a.h"
#include "nfc_mf1.h"
#include "mf1_dict.h"
#include "lf_reader_main.h"

#define CFG_VERSION      1
#define MODE_NAME        "autoclone"
#define MFC1K_SECTORS    16
#define MFC1K_BLOCKS     64
#define BLK_SIZE         16
#define MFC_BLK(sec, i)  ((uint8_t)((sec) * 4 + (i)))


typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t also_slot;      /* 1 = also clone source into the active slot */
    uint8_t reserved[2];
}
cfg_t;
_Static_assert(sizeof(cfg_t) == 4, "autoclone cfg_t must be 4 bytes");

/* Result record (11 bytes): result, uid_len, uid[7], blocks_written */
#define RES_OK           0
#define RES_NO_SOURCE    1
#define RES_NO_TARGET    2
#define RES_WRITE_FAIL   3
#define REC_SIZE             11
#define RESULT_BUFFER_BYTES  (8 * REC_SIZE)

static struct {
    cfg_t    cfg;
    bool     active;
    bool     have_source;
    bool     src_is_lf;      /* source was an LF EM410x tag, not HF 14A */
    uint8_t  em_scan[7];     /* scan_em410x output: [tag_type:2][id:5] when src_is_lf */
    picc_14a_tag_t src_tag;
    uint8_t  src[MFC1K_BLOCKS][BLK_SIZE];
    bool     valid[MFC1K_BLOCKS];
    size_t   write_cursor;
    size_t   read_cursor;
    uint8_t  buffer[RESULT_BUFFER_BYTES];
}
m_st;

static void apply_defaults(cfg_t *c) {
    memset(c, 0, sizeof(*c));
    c->version   = CFG_VERSION;
    c->also_slot = 0;
}

static bool cfg_valid(const cfg_t *c) {
    return c->version == CFG_VERSION && c->also_slot <= 1;
}

static void record(uint8_t result, const picc_14a_tag_t *tag, uint8_t written) {
    if (m_st.write_cursor + REC_SIZE > RESULT_BUFFER_BYTES) return;
    uint8_t *r = &m_st.buffer[m_st.write_cursor];
    memset(r, 0, REC_SIZE);
    r[0] = result;
    if (tag) {
        r[1] = tag->uid_len;
        memcpy(&r[2], tag->uid, tag->uid_len > 7 ? 7 : tag->uid_len);
    }
    r[9]  = written;
    m_st.write_cursor += REC_SIZE;
}

/* LF result: log the 5-byte EM410x id instead of a 14A tag. */
static void record_lf(uint8_t result, uint8_t written) {
    if (m_st.write_cursor + REC_SIZE > RESULT_BUFFER_BYTES) return;
    uint8_t *r = &m_st.buffer[m_st.write_cursor];
    memset(r, 0, REC_SIZE);
    r[0] = result;
    r[1] = 5;
    memcpy(&r[2], &m_st.em_scan[2], 5);
    r[9] = written;
    m_st.write_cursor += REC_SIZE;
}

static void reader_on(void) {
    if (get_device_mode() != DEVICE_MODE_READER) {
        reader_mode_enter();
        bsp_delay_ms(8);
    }
    pcd_14a_reader_antenna_on();
    bsp_delay_ms(8);
}

// Block 0 (UID clone) built from the anticollision scan — no key required.
static void build_block0(uint8_t *b0, const picc_14a_tag_t *tag) {
    memset(b0, 0, BLK_SIZE);
    if (tag->cascade == 1) {            // 4-byte UID (standard gen1a 1K)
        memcpy(b0, tag->uid, 4);
        nfc_tag_14a_create_bcc(b0, 4, &b0[4]);
        b0[5] = tag->sak;
        b0[6] = tag->atqa[0];
        b0[7] = tag->atqa[1];
    } else {                            // 7/10-byte: copy what fits, best effort
        memcpy(b0, tag->uid, tag->uid_len > BLK_SIZE ? BLK_SIZE : tag->uid_len);
    }
}

// Find a working key of `type` for this sector from the dict. Re-selects each try.
static bool find_key(uint8_t sec, uint8_t type, uint8_t out[6]) {
    for (uint8_t k = 0; k < MF1_DICT_COUNT; k++) {
        bsp_wdt_feed();
        picc_14a_tag_t t;
        if (pcd_14a_reader_scan_auto(&t) != STATUS_HF_TAG_OK) continue;
        if (pcd_14a_reader_mf1_auth(&t, type, MFC_BLK(sec, 3), (uint8_t *)MF1_DICT[k]) == STATUS_HF_TAG_OK) {
            memcpy(out, MF1_DICT[k], 6);
            return true;
        }
    }
    return false;
}

/* Capture the source: always clone the UID (keyless); read data sectors whose
 * key is in the dict. Returns the number of valid blocks buffered (>=1). */
static uint8_t read_source(void) {
    memset(m_st.valid, 0, sizeof(m_st.valid));
    build_block0(m_st.src[0], &m_st.src_tag);   // UID clone works on any card
    m_st.valid[0] = true;

    for (uint8_t sec = 0; sec < MFC1K_SECTORS; sec++) {
        bsp_wdt_feed();
        uint8_t ka[6];
        if (!find_key(sec, PICC_AUTHENT1A, ka)) continue;   // unknown key -> skip data
        picc_14a_tag_t t;
        if (pcd_14a_reader_scan_auto(&t) != STATUS_HF_TAG_OK) continue;
        if (pcd_14a_reader_mf1_auth(&t, PICC_AUTHENT1A, MFC_BLK(sec, 3), ka) != STATUS_HF_TAG_OK) continue;
        for (uint8_t i = 0; i < 4; i++) {
            uint8_t blk = MFC_BLK(sec, i);
            if (sec == 0 && i == 0) continue;               // keep constructed block 0
            if (pcd_14a_reader_mf1_read(blk, m_st.src[blk]) == STATUS_HF_TAG_OK)
                m_st.valid[blk] = true;
        }
        uint8_t tr = MFC_BLK(sec, 3);
        if (m_st.valid[tr]) {
            memcpy(&m_st.src[tr][0], ka, 6);                // key A proven by the auth
            uint8_t kb[6];
            if (find_key(sec, PICC_AUTHENT1B, kb)) memcpy(&m_st.src[tr][10], kb, 6);
        }
    }
    pcd_14a_reader_mf1_unauth();

    uint8_t valid = 0;
    for (uint8_t b = 0; b < MFC1K_BLOCKS; b++) if (m_st.valid[b]) valid++;
    return valid;
}

/* Write buffered blocks to a gen1a magic card. Returns blocks written. */
static uint8_t write_magic(void) {
    uint8_t written = 0;
    if (pcd_14a_reader_gen1a_unlock() != STATUS_HF_TAG_OK) return 0;
    for (uint8_t blk = 0; blk < MFC1K_BLOCKS; blk++) {
        bsp_wdt_feed();
        if (!m_st.valid[blk]) continue;
        if (pcd_14a_reader_mf1_write(blk, m_st.src[blk]) == STATUS_HF_TAG_OK) written++;
    }
    pcd_14a_reader_gen1a_uplock();
    return written;
}

/* Clone the buffered source into the active slot (cfg.also_slot). */
static void clone_to_slot(void) {
    uint8_t slot = tag_emulation_get_slot();
    tag_emulation_change_type(slot, TAG_TYPE_MIFARE_1024);
    tag_data_buffer_t *buf = get_buffer_by_tag_type(TAG_TYPE_MIFARE_1024);
    if (buf == NULL) return;
    nfc_tag_mf1_information_t *info = (nfc_tag_mf1_information_t *)buf->buffer;

    nfc_tag_14a_coll_res_entity_t *res = &info->res_coll;
    res->size = (nfc_tag_14a_uid_size)m_st.src_tag.uid_len;
    memcpy(res->uid, m_st.src_tag.uid, m_st.src_tag.uid_len);
    memcpy(res->atqa, m_st.src_tag.atqa, 2);
    res->sak[0]     = m_st.src_tag.sak;
    res->ats.length = m_st.src_tag.ats_len;
    memcpy(res->ats.data, m_st.src_tag.ats, m_st.src_tag.ats_len);

    for (uint8_t blk = 0; blk < MFC1K_BLOCKS; blk++)
        if (m_st.valid[blk]) memcpy(info->memory[blk], m_st.src[blk], BLK_SIZE);

    tag_emulation_save();
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    apply_defaults(&m_st.cfg);
    if (cfg != NULL && cfg_len == sizeof(cfg_t)) {
        cfg_t p;
        memcpy(&p, cfg, sizeof(p));
        if (cfg_valid(&p)) m_st.cfg = p;
        else NRF_LOG_WARNING(MODE_NAME ": invalid cfg, using defaults");
    }
    m_st.active      = true;
    m_st.have_source = false;
    NRF_LOG_INFO(MODE_NAME ": armed");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    m_st.active      = false;
    m_st.have_source = false;
    if (get_device_mode() == DEVICE_MODE_READER) tag_mode_enter();
    return STANDALONE_RC_OK;
}

/* LF fallback: read an EM410x tag. scan_em410x() drives the 125kHz radio
 * itself, so we only ensure reader mode and keep the HF antenna off. */
static bool read_source_lf(void) {
    if (get_device_mode() != DEVICE_MODE_READER) {
        reader_mode_enter();
        bsp_delay_ms(8);
    }
    pcd_14a_reader_antenna_off();
    return scan_em410x(m_st.em_scan) == STATUS_LF_TAG_OK;
}

/* Write the captured EM410x ID to a T5577. write_em410x_to_t55xx() drives the
 * 125kHz radio itself. */
static uint8_t write_lf_t55xx(void) {
    if (get_device_mode() != DEVICE_MODE_READER) {
        reader_mode_enter();
        bsp_delay_ms(8);
    }
    pcd_14a_reader_antenna_off();
    uint8_t zero[4] = {0};
    return write_em410x_to_t55xx(&m_st.em_scan[2], zero, zero, 0) == STATUS_LF_TAG_OK ? 1 : 0;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (!m_st.active) return STANDALONE_RC_INVALID_STATE;

    if (evt == STANDALONE_BTN_BOTH_VLONG) {
        m_st.have_source  = false;
        m_st.write_cursor = 0;
        m_st.read_cursor  = 0;
        standalone_feedback(SL_FB_SUCCESS);
        return STANDALONE_RC_OK;
    }
    if (evt != STANDALONE_BTN_BOTH_SHORT) return STANDALONE_RC_OK;

    standalone_feedback(SL_FB_BUSY_START);

    if (!m_st.have_source) {
        /* Step 1: capture the source (UID always, data where keys are known). */
        reader_on();
        uint8_t st = pcd_14a_reader_scan_auto(&m_st.src_tag);
        uint8_t valid = (st == STATUS_HF_TAG_OK) ? read_source() : 0;
        pcd_14a_reader_antenna_off();

        if (st == STATUS_HF_TAG_OK && valid > 0) {
            m_st.have_source = true;
            m_st.src_is_lf   = false;
            if (m_st.cfg.also_slot) clone_to_slot();
            tag_mode_enter();
            standalone_feedback(SL_FB_SUCCESS);   /* present the target, press again */
            return STANDALONE_RC_OK;
        }

        /* No HF source: fall back to LF (EM410x -> T5577). */
        if (read_source_lf()) {
            m_st.have_source = true;
            m_st.src_is_lf   = true;
            tag_mode_enter();
            standalone_feedback(SL_FB_SUCCESS);   /* present a T5577, press again */
            return STANDALONE_RC_OK;
        }

        tag_mode_enter();
        record(RES_NO_SOURCE, (st == STATUS_HF_TAG_OK) ? &m_st.src_tag : NULL, 0);
        standalone_feedback(SL_FB_ERROR);
        return STANDALONE_RC_NO_TAG;
    }

    /* Step 2: write the buffered card to the target now present. */
    uint8_t written;
    if (m_st.src_is_lf) {
        written = write_lf_t55xx();          /* EM410x -> T5577 */
    } else {
        reader_on();
        picc_14a_tag_t target;
        uint8_t st = pcd_14a_reader_scan_auto(&target);
        if (st != STATUS_HF_TAG_OK) {
            pcd_14a_reader_antenna_off();
            tag_mode_enter();
            record(RES_NO_TARGET, &m_st.src_tag, 0);
            standalone_feedback(SL_FB_ERROR);
            return STANDALONE_RC_NO_TAG;
        }
        written = write_magic();
        pcd_14a_reader_antenna_off();
    }
    tag_mode_enter();
    m_st.have_source = false;
    if (m_st.src_is_lf)
        record_lf(written > 0 ? RES_OK : RES_WRITE_FAIL, written);
    else
        record(written > 0 ? RES_OK : RES_WRITE_FAIL, &m_st.src_tag, written);
    standalone_feedback(written > 0 ? SL_FB_SUCCESS : SL_FB_ERROR);
    return written > 0 ? STANDALONE_RC_OK : STANDALONE_RC_WRITE_FAIL;
}

static size_t get_result_size(void) {
    return m_st.write_cursor;
}

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (!out || !out_len) return STANDALONE_RC_INVALID_CFG;
    if (m_st.read_cursor >= m_st.write_cursor) {
        /* End of buffer: rewind so a later get-result re-reads the same
         * results. They persist until clear-result / CLEAR. */
        m_st.read_cursor = 0;
        *out_len = 0;
        return STANDALONE_RC_NO_RESULT;
    }
    size_t rem  = m_st.write_cursor - m_st.read_cursor;
    size_t take = rem < out_max ? rem : out_max;
    memcpy(out, &m_st.buffer[m_st.read_cursor], take);
    m_st.read_cursor += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    m_st.write_cursor = 0;
    m_st.read_cursor  = 0;
}

const standalone_mode_iface_t mode_autoclone_iface = {
    .id              = STANDALONE_MODE_AUTOCLONE,
    .name            = MODE_NAME,
    .writes_tag      = true,
    .writes_slot     = true,
    .wants_tick      = false,
    .on_enter        = on_enter,
    .on_exit         = on_exit,
    .on_button       = on_button,
    .on_tick         = NULL,
    .get_result_size = get_result_size,
    .read_result     = read_result,
    .clear_result    = clear_result,
    .ensure_loaded   = NULL,
};

#endif /* PROJECT_CHAMELEON_ULTRA */
