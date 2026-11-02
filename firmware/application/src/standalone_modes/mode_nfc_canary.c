/*
 * mode_nfc_canary.c
 *
 * Standalone mode: the CU sits armed as a bait card and tells you when an NFC
 * reader probes it. Works on Lite and Ultra (NFCT only, no reader hardware).
 *
 * All decision logic (probe classification, alert/cooldown windows, wire
 * formats, log ring) lives in nfc_canary_core.c and is unit-tested natively.
 * This file is the thin glue:
 *
 *   ISR     NFCT field-edge + RX-frame callbacks bump counters (nc_snapshot_t).
 *   tick    copy counters, nc_step(), act on the returned actions:
 *             ALERT -> BLE notification (if enabled + connected), LED flash
 *             END   -> append 16-byte record to the log, BLE summary
 *   result  the log: 16-byte records, oldest first (see nfc_canary_core.h)
 *
 * The active emulation slot is the bait. A slot with a real HF tag makes
 * readers progress to SELECT / ENGAGE; an empty slot will mostly only ever
 * reach FIELD / POLL.
 *
 * Buttons: ACTION = send a TEST event over BLE (verifies the alert path)
 *          TOGGLE = arm / disarm (framework)
 *          CLEAR  = clear the log
 *
 * Persistence: the log is flushed to FDS at most every FLUSH_MIN_S seconds
 * (flash wear + the multi-second stall FDS GC can cause) and always on
 * disarm. A power loss while armed can lose up to that many seconds of
 * records.
 *
 * Power: while armed the sleep timer is held off, so the device stays awake.
 * Expect it to drain a battery in days, not weeks.
 */

#include "app_standalone.h"
#include "standalone_led.h"
#include "nfc_canary_core.h"

#include <string.h>

#include "nrf_log.h"
#include "app_timer.h"
#include "app_util_platform.h"

#include "app_status.h"
#include "data_cmd.h"
#include "dataframe.h"
#include "ble_main.h"
#include "tag_emulation.h"
#include "utils/syssleep.h"
#include "rfid/nfctag/hf/nfc_14a.h"

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */

/* The framework persists at most STANDALONE_RESULT_PERSIST_MAX - 4 = 2080
 * data bytes per mode = exactly 130 sixteen-byte records. */
#define CANARY_LOG_BYTES      (130u * NC_REC_SIZE)
_Static_assert(CANARY_LOG_BYTES + 4 <= STANDALONE_RESULT_PERSIST_MAX,
               "canary log must fit the framework's persisted result record");

#define CANARY_TICK_MS        250u
#define FLUSH_MIN_S           30u

#define TICKS_PER_S           APP_TIMER_TICKS(1000)

/* -------------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------------- */

/* ISR-written counters. Only touched in ISR context or inside a critical
 * region; never read directly from the main loop. */
static nc_snapshot_t m_isr;

static uint32_t m_log_words[(CANARY_LOG_BYTES + 3) / 4];
#define m_log ((uint8_t *)m_log_words)

static struct {
    nc_t      nc;
    nc_cfg_t  cfg;
    bool      active;
    bool      loaded;
    bool      dirty;
    uint8_t   seq;          /* BLE event sequence */
    uint8_t   epoch;        /* arm counter, stored in each record */
    size_t    used;         /* valid log bytes */
    size_t    read_cursor;
    uint64_t  ticks_acc;    /* RTC ticks since arm (the RTC is only 24 bit) */
    uint32_t  last_ticks;
    uint32_t  last_flush_s;
} m_st;

/* -------------------------------------------------------------------------
 * ISR callbacks - no blocking, no FDS, no LED, no BLE
 * ------------------------------------------------------------------------- */

static void canary_rx_cb(const uint8_t *data, uint16_t bits) {
    int lv = nc_classify(data, bits);
    if (lv == NC_LV_NONE) return;
    m_isr.cnt[lv]++;
    m_isr.cmd[lv] = data[0];
}

static void canary_field_cb(bool present) {
    m_isr.field_present = present;
    if (present) m_isr.cnt[NC_LV_FIELD]++;
}

static void isr_snapshot(nc_snapshot_t *out) {
    CRITICAL_REGION_ENTER();
    *out = m_isr;
    CRITICAL_REGION_EXIT();
}

/* -------------------------------------------------------------------------
 * Time
 * ------------------------------------------------------------------------- */

/* Seconds since arm. Accumulates RTC tick deltas so the 24-bit counter wrap
 * (every ~512 s) is invisible; relies on being called more often than that. */
static uint32_t seconds_since_arm(uint32_t now_ticks) {
    m_st.ticks_acc += app_timer_cnt_diff_compute(now_ticks, m_st.last_ticks);
    m_st.last_ticks = now_ticks;
    return (uint32_t)(m_st.ticks_acc / TICKS_PER_S);
}

/* -------------------------------------------------------------------------
 * Log
 * ------------------------------------------------------------------------- */

static void log_ensure_loaded(void) {
    if (m_st.loaded) return;
    m_st.loaded = true;

    size_t n = 0;
    if (app_standalone_load_result_buf(STANDALONE_MODE_NFC_CANARY, m_log_words,
                                       CANARY_LOG_BYTES, &n) != STANDALONE_RC_OK) {
        n = 0;
    }
    n -= n % NC_REC_SIZE;               /* drop a torn trailing record */
    m_st.used = n;
    m_st.read_cursor = 0;
    /* Continue the arm counter from the newest record so epochs stay
     * monotonic across reboots. */
    m_st.epoch = (n >= NC_REC_SIZE) ? m_log[n - NC_REC_SIZE + 3] : 0;
    NRF_LOG_INFO("canary: loaded %u record(s)", (unsigned)(n / NC_REC_SIZE));
}

static void log_flush(uint32_t now_s) {
    if (!m_st.dirty) return;
    app_standalone_save_result_buf(STANDALONE_MODE_NFC_CANARY, m_log_words, m_st.used);
    m_st.dirty = false;
    m_st.last_flush_s = now_s;
}

static void log_add(const nc_action_t *end) {
    uint8_t rec[NC_REC_SIZE];
    bool dropped = false;
    nc_rec_pack(rec, end, m_st.epoch);
    m_st.used = nc_log_append(m_log, CANARY_LOG_BYTES, m_st.used, rec, &dropped);
    if (dropped) {
        /* Oldest record evicted: everything shifted down one record. */
        m_st.read_cursor = (m_st.read_cursor >= NC_REC_SIZE)
                           ? m_st.read_cursor - NC_REC_SIZE : 0;
    }
    m_st.dirty = true;
}

/* -------------------------------------------------------------------------
 * Output
 * ------------------------------------------------------------------------- */

static bool ble_emit(uint8_t type, const nc_action_t *a) {
    uint8_t payload[NC_EVT_PAYLOAD_SIZE];
    /* seq advances even when nobody is listening, so a gap seen by the host
     * after reconnecting reveals events it missed. */
    nc_evt_pack(payload, type, a, m_st.seq++);

    if (!is_nus_working()) return false;
    data_frame_tx_t *tx = data_frame_make(DATA_CMD_STANDALONE_CANARY_EVENT,
                                          STATUS_SUCCESS, sizeof(payload), payload);
    if (tx == NULL) return false;
    nus_data_response(tx->buffer, tx->length);
    return true;
}

static bool led_allowed(void) {
    return !(app_standalone_get_flags() & STANDALONE_FLAG_LED_QUIET);
}

static void handle_action(const nc_action_t *a) {
    if (a->kind == NC_ACT_ALERT) {
        NRF_LOG_INFO("canary: ALERT level=%u cmd=0x%02x", a->level, a->cmd);
        if (m_st.cfg.flags & NC_CFG_FLAG_BLE_ALERT) ble_emit(NC_EVT_ALERT, a);
        if (led_allowed()) standalone_feedback(SL_FB_ERROR);
    } else if (a->kind == NC_ACT_END) {
        NRF_LOG_INFO("canary: END level=%u dur=%us report=%u",
                     a->level, (unsigned)a->dur_s, a->report);
        if (!a->report) return;
        log_add(a);
        if (m_st.cfg.flags & NC_CFG_FLAG_BLE_END) ble_emit(NC_EVT_END, a);
    }
}

/* Snapshot the ISR counters, advance the state machine, act on the result. */
static void poll(uint32_t now_ticks) {
    nc_snapshot_t snap;
    nc_action_t   act[2];

    isr_snapshot(&snap);
    uint32_t now_s = seconds_since_arm(now_ticks);

    size_t n = nc_step(&m_st.nc, &snap, now_s, act);
    for (size_t i = 0; i < n; i++) handle_action(&act[i]);

    if (m_st.dirty && (now_s - m_st.last_flush_s) >= FLUSH_MIN_S) {
        log_flush(now_s);
    }
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    if (!nc_cfg_parse(cfg, cfg_len, &m_st.cfg)) {
        NRF_LOG_WARNING("canary: bad cfg, using defaults");
    }
    log_ensure_loaded();
    m_st.epoch++;
    m_st.seq          = 0;
    m_st.ticks_acc    = 0;
    m_st.last_ticks   = app_timer_cnt_get();
    m_st.last_flush_s = 0;
    m_st.dirty        = false;

    /* Hook first, then baseline, so nothing between the two is lost or
     * double counted. Whatever the ISR counted before arming is ignored. */
    memset(&m_isr, 0, sizeof(m_isr));
    tag_emulation_load_data();
    nfc_tag_14a_set_sniff_cb(canary_rx_cb);
    nfc_tag_14a_set_field_sniff_cb(canary_field_cb);

    nc_snapshot_t base;
    isr_snapshot(&base);
    nc_init(&m_st.nc, &m_st.cfg, &base);

    m_st.active = true;
    NRF_LOG_INFO("canary: armed min_level=%u cooldown=%us flags=0x%02x epoch=%u",
                 m_st.cfg.min_level, m_st.cfg.cooldown_s, m_st.cfg.flags, m_st.epoch);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    if (!m_st.active) return STANDALONE_RC_OK;

    /* Pick up anything the ISR counted since the last tick, then stop
     * listening. */
    poll(app_timer_cnt_get());
    nfc_tag_14a_clear_sniff_cb();
    nfc_tag_14a_clear_field_sniff_cb();
    m_st.active = false;

    nc_action_t end;
    uint32_t now_s = (uint32_t)(m_st.ticks_acc / TICKS_PER_S);
    if (nc_close(&m_st.nc, now_s, &end)) handle_action(&end);

    log_flush(now_s);
    NRF_LOG_INFO("canary: disarmed");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ticks) {
    if (!m_st.active) return STANDALONE_RC_OK;

    /* A canary that falls asleep is useless (and an unattended System-OFF
     * wake would come back DISARMED). Hold the sleep timer off while armed;
     * BLE disconnects and field-lost events restart it. */
    sleep_timer_stop();

    poll(now_ticks);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (!m_st.active) return STANDALONE_RC_INVALID_STATE;

    switch (evt) {
        case STANDALONE_BTN_BOTH_SHORT: {
            /* Fire a TEST event so you can verify the BLE alert path from
             * the phone before walking away. Red = nobody is connected. */
            bool sent = ble_emit(NC_EVT_TEST, NULL);
            if (led_allowed()) standalone_feedback(sent ? SL_FB_SUCCESS : SL_FB_ERROR);
            return STANDALONE_RC_OK;
        }

        case STANDALONE_BTN_BOTH_VLONG:
            m_st.used        = 0;
            m_st.read_cursor = 0;
            m_st.dirty       = true;
            log_flush((uint32_t)(m_st.ticks_acc / TICKS_PER_S));
            NRF_LOG_INFO("canary: log cleared");
            if (led_allowed()) standalone_feedback(SL_FB_SUCCESS);
            return STANDALONE_RC_OK;

        default:
            return STANDALONE_RC_OK;
    }
}

/* -------------------------------------------------------------------------
 * Result retrieval (the log, oldest record first)
 * ------------------------------------------------------------------------- */

static void ensure_loaded(void) { log_ensure_loaded(); }

static size_t get_result_size(void) {
    log_ensure_loaded();
    return m_st.used;
}

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) return STANDALONE_RC_INVALID_CFG;
    log_ensure_loaded();

    if (m_st.read_cursor >= m_st.used) {
        m_st.read_cursor = 0;           /* next drain starts from the top */
        *out_len = 0;
        return STANDALONE_RC_NO_RESULT;
    }

    size_t take = m_st.used - m_st.read_cursor;
    if (take > out_max) take = out_max;
    take -= take % NC_REC_SIZE;         /* never split a record across chunks */
    if (take == 0) {
        *out_len = 0;
        return STANDALONE_RC_NO_RESULT;
    }

    memcpy(out, &m_log[m_st.read_cursor], take);
    m_st.read_cursor += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    log_ensure_loaded();
    m_st.used        = 0;
    m_st.read_cursor = 0;
    m_st.dirty       = true;
    log_flush((uint32_t)(m_st.ticks_acc / TICKS_PER_S));
}

/* -------------------------------------------------------------------------
 * Descriptor
 * ------------------------------------------------------------------------- */

const standalone_mode_iface_t mode_nfc_canary_iface = {
    .id               = STANDALONE_MODE_NFC_CANARY,
    .name             = "nfc_canary",
    .writes_tag       = false,
    .writes_slot      = false,
    .wants_tick       = true,
    .tick_interval_ms = CANARY_TICK_MS,
    .on_enter         = on_enter,
    .on_exit          = on_exit,
    .on_button        = on_button,
    .on_tick          = on_tick,
    .get_result_size  = get_result_size,
    .read_result      = read_result,
    .clear_result     = clear_result,
    .ensure_loaded    = ensure_loaded,
};
