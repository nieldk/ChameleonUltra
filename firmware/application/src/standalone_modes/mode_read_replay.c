/*
 * mode_read_replay.c
 *
 * Scan a 14A card and load it into the active slot as MIFARE 1K, then emulate
 * it ("replay"). Clones anti-collision (UID/ATQA/SAK/ATS) always; optionally
 * reads MFC data blocks with the default key. Ultra only (needs RC522).
 *
 * writes_slot -> requires STANDALONE_FLAG_HOST_OPTED_IN to arm.
 */

#include "app_standalone.h"
#include "standalone_led.h"

#if defined(PROJECT_CHAMELEON_ULTRA)

#include <string.h>

#include "nrf_log.h"
#include "app_status.h"
#include "rc522.h"           /* pcd_14a_reader_*, PICC_AUTHENT1A, picc_14a_tag_t */
#include "rfid_main.h"       /* reader_mode_enter, tag_mode_enter, get_device_mode */
#include "bsp_delay.h"
#include "bsp_wdt.h"
#include "tag_emulation.h"
#include "tag_base_type.h"
#include "nfc_14a.h"
#include "nfc_mf1.h"

#define CFG_VERSION      1
#define MODE_NAME        "read_replay"
#define MFC1K_SECTORS    16
#define MFC_BLK(sec, i)  ((uint8_t)((sec) * 4 + (i)))

static const uint8_t DEFAULT_KEY[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t read_blocks;    /* 0 = anti-coll only, 1 = also read data blocks */
    uint8_t reserved[2];
}
cfg_t;
_Static_assert(sizeof(cfg_t) == 4, "read_replay cfg_t must be 4 bytes");

/* Result record (13 bytes): uid_len, uid[7], atqa[2], sak, sectors_read, sectors_total */
#define REC_SIZE             13
#define RESULT_BUFFER_BYTES  (8 * REC_SIZE)

static struct {
    cfg_t    cfg;
    bool     active;
    size_t   write_cursor;
    size_t   read_cursor;
    uint8_t  buffer[RESULT_BUFFER_BYTES];
}
m_st;

static void apply_defaults(cfg_t *c) {
    memset(c, 0, sizeof(*c));
    c->version     = CFG_VERSION;
    c->read_blocks = 1;
}

static bool cfg_valid(const cfg_t *c) {
    return c->version == CFG_VERSION && c->read_blocks <= 1;
}

static void record(const picc_14a_tag_t *tag, uint8_t read, uint8_t total) {
    if (m_st.write_cursor + REC_SIZE > RESULT_BUFFER_BYTES) return;
    uint8_t *r = &m_st.buffer[m_st.write_cursor];
    memset(r, 0, REC_SIZE);
    r[0] = tag->uid_len;
    memcpy(&r[1], tag->uid, tag->uid_len > 7 ? 7 : tag->uid_len);
    r[8] = tag->atqa[0];
    r[9] = tag->atqa[1];
    r[10] = tag->sak;
    r[11] = read;
    r[12] = total;
    m_st.write_cursor += REC_SIZE;
}

/* Clone identity (and optionally data blocks) into the active slot. Antenna
 * must already be on. Returns the number of sectors successfully read. */
static uint8_t clone_to_slot(const picc_14a_tag_t *tag) {
    uint8_t slot = tag_emulation_get_slot();
    tag_emulation_change_type(slot, TAG_TYPE_MIFARE_1024);

    tag_data_buffer_t *buf = get_buffer_by_tag_type(TAG_TYPE_MIFARE_1024);
    if (buf == NULL) return 0;
    nfc_tag_mf1_information_t *info = (nfc_tag_mf1_information_t *)buf->buffer;

    nfc_tag_14a_coll_res_entity_t *res = &info->res_coll;
    res->size = (nfc_tag_14a_uid_size)tag->uid_len;
    memcpy(res->uid, tag->uid, tag->uid_len);
    memcpy(res->atqa, tag->atqa, 2);
    res->sak[0]     = tag->sak;
    res->ats.length = tag->ats_len;
    memcpy(res->ats.data, tag->ats, tag->ats_len);

    uint8_t read = 0;
    if (m_st.cfg.read_blocks) {
        for (uint8_t sec = 0; sec < MFC1K_SECTORS; sec++) {
            bsp_wdt_feed();
            picc_14a_tag_t t;    /* re-select before each sector auth */
            if (pcd_14a_reader_scan_auto(&t) != STATUS_HF_TAG_OK) continue;
            if (pcd_14a_reader_mf1_auth(&t, PICC_AUTHENT1A, MFC_BLK(sec, 3),
                                        (uint8_t *)DEFAULT_KEY) != STATUS_HF_TAG_OK) continue;
            for (uint8_t i = 0; i < 4; i++) {
                uint8_t blk = MFC_BLK(sec, i);
                pcd_14a_reader_mf1_read(blk, info->memory[blk]);   /* best effort */
            }
            read++;
        }
        pcd_14a_reader_mf1_unauth();
    }

    tag_emulation_save();
    return read;
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    apply_defaults(&m_st.cfg);
    if (cfg != NULL && cfg_len == sizeof(cfg_t)) {
        cfg_t p;
        memcpy(&p, cfg, sizeof(p));
        if (cfg_valid(&p)) m_st.cfg = p;
        else NRF_LOG_WARNING(MODE_NAME ": invalid cfg, using defaults");
    }
    m_st.active = true;
    NRF_LOG_INFO(MODE_NAME ": armed");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    m_st.active = false;
    if (get_device_mode() == DEVICE_MODE_READER) tag_mode_enter();
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (!m_st.active) return STANDALONE_RC_INVALID_STATE;

    if (evt == STANDALONE_BTN_BOTH_VLONG) {
        m_st.write_cursor = 0;
        m_st.read_cursor  = 0;
        standalone_feedback(SL_FB_SUCCESS);
        return STANDALONE_RC_OK;
    }
    if (evt != STANDALONE_BTN_BOTH_SHORT) return STANDALONE_RC_OK;

    standalone_feedback(SL_FB_BUSY_START);
    if (get_device_mode() != DEVICE_MODE_READER) {
        reader_mode_enter();
        bsp_delay_ms(8);
    }

    pcd_14a_reader_antenna_on();
    bsp_delay_ms(8);
    picc_14a_tag_t tag;
    uint8_t st = pcd_14a_reader_scan_auto(&tag);
    uint8_t read = 0, total = m_st.cfg.read_blocks ? MFC1K_SECTORS : 0;
    if (st == STATUS_HF_TAG_OK) read = clone_to_slot(&tag);
    pcd_14a_reader_antenna_off();

    tag_mode_enter();   /* back to emulation so the clone is live */

    if (st == STATUS_HF_TAG_OK) {
        record(&tag, read, total);
        standalone_feedback(SL_FB_SUCCESS);
        return STANDALONE_RC_OK;
    }
    standalone_feedback(SL_FB_ERROR);
    return STANDALONE_RC_NO_TAG;
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

const standalone_mode_iface_t mode_read_replay_iface = {
    .id              = STANDALONE_MODE_READ_REPLAY,
    .name            = MODE_NAME,
    .writes_tag      = false,
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
