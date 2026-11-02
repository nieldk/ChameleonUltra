/*
 * mode_dict_check.c
 *
 * Scan a MIFARE Classic card and test a small built-in key dictionary against
 * each sector (key A and key B). Logs the keys found per sector. Ultra only.
 * Read-only: does not write tag or slot.
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
#include "mf1_dict.h"

#define CFG_VERSION      1
#define MODE_NAME        "dict_check"
#define MFC1K_SECTORS    16
#define MFC_TRAILER(sec) ((uint8_t)((sec) * 4 + 3))


typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t sectors;        /* sectors to test, 1..16 */
    uint8_t reserved[2];
}
cfg_t;
_Static_assert(sizeof(cfg_t) == 4, "dict_check cfg_t must be 4 bytes");

/* Result record (15 bytes): sector, found_a, keyA[6], found_b, keyB[6] */
#define REC_SIZE             15
#define RESULT_BUFFER_BYTES  (MFC1K_SECTORS * REC_SIZE)

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
    c->version = CFG_VERSION;
    c->sectors = MFC1K_SECTORS;
}

static bool cfg_valid(const cfg_t *c) {
    return c->version == CFG_VERSION && c->sectors >= 1 && c->sectors <= MFC1K_SECTORS;
}

/* Try the dictionary against one sector/key-type. Copies the key out on hit. */
static bool try_keys(uint8_t sector, uint8_t key_type, uint8_t out_key[6]) {
    for (uint8_t k = 0; k < MF1_DICT_COUNT; k++) {
        bsp_wdt_feed();
        picc_14a_tag_t t;    /* a failed auth halts the card; re-select each try */
        if (pcd_14a_reader_scan_auto(&t) != STATUS_HF_TAG_OK) continue;
        if (pcd_14a_reader_mf1_auth(&t, key_type, MFC_TRAILER(sector),
                                    (uint8_t *)MF1_DICT[k]) == STATUS_HF_TAG_OK) {
            memcpy(out_key, MF1_DICT[k], 6);
            pcd_14a_reader_mf1_unauth();
            return true;
        }
    }
    return false;
}

static void run_check(void) {
    m_st.write_cursor = 0;
    m_st.read_cursor  = 0;
    for (uint8_t sec = 0; sec < m_st.cfg.sectors; sec++) {
        uint8_t key_a[6] = {0}, key_b[6] = {0};
        bool found_a = try_keys(sec, PICC_AUTHENT1A, key_a);
        bool found_b = try_keys(sec, PICC_AUTHENT1B, key_b);

        if (m_st.write_cursor + REC_SIZE > RESULT_BUFFER_BYTES) break;
        uint8_t *r = &m_st.buffer[m_st.write_cursor];
        r[0] = sec;
        r[1] = found_a;
        memcpy(&r[2], key_a, 6);
        r[8] = found_b;
        memcpy(&r[9], key_b, 6);
        m_st.write_cursor += REC_SIZE;
    }
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
    if (st == STATUS_HF_TAG_OK) run_check();
    pcd_14a_reader_antenna_off();
    tag_mode_enter();

    if (st != STATUS_HF_TAG_OK) {
        standalone_feedback(SL_FB_ERROR);
        return STANDALONE_RC_NO_TAG;
    }
    standalone_feedback(SL_FB_SUCCESS);
    return STANDALONE_RC_OK;
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

const standalone_mode_iface_t mode_dict_check_iface = {
    .id              = STANDALONE_MODE_DICT_CHECK,
    .name            = MODE_NAME,
    .writes_tag      = false,
    .writes_slot     = false,
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
