/*
 * logflash.c - persistent debug log.
 *
 * NRF_LOG backend that writes formatted text into a RAM ring (survives soft
 * resets), which is drained into a flash ring (see common/logring.h). The
 * bootloader exposes the flash ring as LOG.TXT on the UF2 drive.
 *
 * No NRF_LOG_* macros in this file: logging from the logger would recurse.
 */
#include "logflash.h"

#include <string.h>

#include "app_timer.h"
#include "app_util_platform.h"
#include "logring.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "nrf_log.h"
#include "nrf_log_backend_interface.h"
#include "nrf_log_backend_serial.h"
#include "nrf_log_ctrl.h"
#include "nrf_sdh.h"
#include "sdk_config.h"

/* The ring must stay below the FDS area (FDS ends at the bootloader, 0xF3000). */
_Static_assert(LOGRING_BASE + LOGRING_SIZE <=
               0xF3000UL - (FDS_VIRTUAL_PAGES + FDS_VIRTUAL_PAGES_RESERVED) * FDS_VIRTUAL_PAGE_SIZE * 4UL,
               "log ring overlaps FDS");

#define LF_RAM_SIZE       2048u            /* power of two */
#define LF_RAM_MAGIC      0x4C464C47u
#define LF_CHUNK_MAX      256u
#define LF_IDLE_FLUSH_MS  500u

typedef struct {
    uint32_t magic;
    uint32_t head;      /* bytes ever appended */
    uint32_t flushed;   /* bytes ever written to flash */
    uint32_t boots;
    uint8_t  buf[LF_RAM_SIZE];
} lf_ram_t;

static lf_ram_t m_ram __attribute__((section(".noinit_logflash"), aligned(4)));

typedef enum { STEP_ERASE, STEP_HDR, STEP_DATA } step_t;
typedef enum { OP_NONE, OP_ERASE, OP_HDR, OP_DATA, OP_CLEAR } op_t;

static volatile bool     m_busy;
static volatile op_t     m_op;
static volatile step_t   m_step;
static volatile uint32_t m_wr;              /* write offset in the ring */
static volatile uint32_t m_next_seq;
static volatile uint32_t m_inflight;
static volatile bool     m_failed;
static volatile uint32_t m_err;             /* stage<<24 | op<<16 | code, first failure */
static volatile bool     m_force;
static volatile bool     m_clear_req;
static volatile uint32_t m_clear_page;
static bool              m_fs_ready;
static uint32_t          m_dropped;
static uint32_t          m_last_append;
static uint8_t           m_level;
static int32_t           m_backend_id = -1;
static logring_hdr_t     m_hdr __attribute__((aligned(4)));

static void fs_evt(nrf_fstorage_evt_t *p_evt);

NRF_FSTORAGE_DEF(nrf_fstorage_t m_logflash_fs) = {
    .evt_handler = fs_evt,
    .start_addr  = LOGRING_BASE,
    .end_addr    = LOGRING_BASE + LOGRING_SIZE,
};

/* ---- RAM ring ---------------------------------------------------------- */

static void ram_copy_in(const char *s, uint32_t n) {
    uint32_t idx = m_ram.head & (LF_RAM_SIZE - 1);
    uint32_t first = LF_RAM_SIZE - idx;
    if (first > n) {
        first = n;
    }
    memcpy(&m_ram.buf[idx], s, first);
    memcpy(&m_ram.buf[0], s + first, n - first);
    m_ram.head += n;
}

static uint32_t utoa_dec(char *out, uint32_t v) {
    char tmp[10];
    uint32_t n = 0, len = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) {
        out[len++] = tmp[--n];
    }
    return len;
}

static uint32_t hex8(char *out, uint32_t v) {
    for (int i = 7; i >= 0; i--) {
        out[7 - i] = "0123456789ABCDEF"[(v >> (i * 4)) & 0xF];
    }
    return 8;
}

static uint32_t cat(char *out, uint32_t pos, const char *s) {
    while (*s) {
        out[pos++] = *s++;
    }
    return pos;
}

/* Append n bytes; drops them (and counts) if the RAM ring is full. */
static void ram_put(const char *s, uint32_t n) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();

    uint32_t pend = m_ram.head - m_ram.flushed;
    char note[48];
    uint32_t nl = 0;

    if (m_dropped && pend + n + sizeof(note) <= LF_RAM_SIZE) {
        nl = cat(note, nl, "\n[logflash: ");
        nl += utoa_dec(note + nl, m_dropped);
        nl = cat(note, nl, " bytes dropped]\n");
        ram_copy_in(note, nl);
        m_dropped = 0;
        pend += nl;
    }
    if (pend + n <= LF_RAM_SIZE) {
        ram_copy_in(s, n);
    } else {
        m_dropped += n;
    }
    m_last_append = app_timer_cnt_get();

    if (!primask) {
        __enable_irq();
    }
}

/* ---- NRF_LOG backend --------------------------------------------------- */

static uint8_t m_strbuf[64];

static void be_tx(void const *ctx, char const *buf, size_t len) {
    ram_put(buf, (uint32_t)len);
}

static void be_put(nrf_log_backend_t const *p_backend, nrf_log_entry_t *p_msg) {
    nrf_log_backend_serial_put(p_backend, p_msg, m_strbuf, sizeof(m_strbuf), be_tx);
}

static void be_flush(nrf_log_backend_t const *p_backend) {}
static void be_panic_set(nrf_log_backend_t const *p_backend) {}

static const nrf_log_backend_api_t m_be_api = {
    .put       = be_put,
    .flush     = be_flush,
    .panic_set = be_panic_set,
};

NRF_LOG_BACKEND_DEF(m_logflash_backend, m_be_api, NULL);

static uint8_t sev_min(uint8_t a, uint8_t b) {
    return a < b ? a : b;
}

void logflash_set_level(uint8_t level) {
    if (level > LOGFLASH_LEVEL_MAX) {
        level = LOGFLASH_LEVEL_MAX;
    }
    m_level = level;
    if (m_backend_id < 0) {
        return;
    }
    uint32_t cnt = nrf_log_module_cnt_get();
    for (uint32_t i = 0; i < cnt; i++) {
        uint8_t compiled = nrf_log_module_filter_get(0, i, false, false);
        nrf_log_module_filter_set((uint32_t)m_backend_id, i, (nrf_log_severity_t)sev_min(compiled, level));
    }
}

void logflash_init(uint8_t level) {
    uint32_t recovered = 0;
    bool valid = m_ram.magic == LF_RAM_MAGIC &&
                 (m_ram.head - m_ram.flushed) <= LF_RAM_SIZE &&
                 (m_ram.flushed & 3) == 0;

    if (valid) {
        recovered = m_ram.head - m_ram.flushed;
        m_ram.boots++;
    } else {
        m_ram.magic   = LF_RAM_MAGIC;
        m_ram.head    = 0;
        m_ram.flushed = 0;
        m_ram.boots   = 1;
    }

    m_backend_id = nrf_log_backend_add(&m_logflash_backend, NRF_LOG_SEVERITY_NONE);
    if (m_backend_id < 0) {
        return;
    }
    nrf_log_backend_enable(&m_logflash_backend);

    /* Filters are now enabled and the compile-time level is DEBUG: keep the
     * backends registered before ours (RTT) at INFO, as before. */
    uint32_t cnt = nrf_log_module_cnt_get();
    for (int32_t b = 0; b < m_backend_id; b++) {
        for (uint32_t i = 0; i < cnt; i++) {
            uint8_t compiled = nrf_log_module_filter_get(0, i, false, false);
            nrf_log_module_filter_set((uint32_t)b, i, (nrf_log_severity_t)sev_min(compiled, NRF_LOG_SEVERITY_INFO));
        }
    }
    logflash_set_level(level);

    if (level > 0 || recovered > 0) {
        char line[96];
        uint32_t n = cat(line, 0, "\n--- boot ");
        n += utoa_dec(line + n, m_ram.boots);
        n = cat(line, n, " rst=0x");
        n += hex8(line + n, NRF_POWER->RESETREAS);
        n = cat(line, n, " recovered=");
        n += utoa_dec(line + n, recovered);
        n = cat(line, n, " level=");
        n += utoa_dec(line + n, level);
        n = cat(line, n, " ---\n");
        ram_put(line, n);
    }
}

/* ---- RAM -> flash pipeline --------------------------------------------- */

static void set_err(uint32_t stage, uint32_t code) {
    if (!m_err) {
        m_err = (stage << 24) | ((uint32_t)m_op << 16) | (code & 0xFFFFu);
    }
}

static void fs_evt(nrf_fstorage_evt_t *p_evt) {
    if (p_evt->result != NRF_SUCCESS) {
        set_err(2, p_evt->result);
        m_failed = true;
        m_op = OP_NONE;
        m_busy = false;
        return;
    }
    switch (m_op) {
        case OP_ERASE:
            m_step = STEP_HDR;
            break;
        case OP_HDR:
            m_wr += LOGRING_HDR_SIZE;
            m_next_seq++;
            m_step = STEP_DATA;
            break;
        case OP_DATA:
            m_ram.flushed += m_inflight;
            m_wr = (m_wr + m_inflight) % LOGRING_SIZE;
            if ((m_wr % LOGRING_PAGE_SIZE) == 0) {
                m_step = STEP_ERASE;
            }
            break;
        case OP_CLEAR:
            if (++m_clear_page >= LOGRING_PAGES) {
                m_clear_req = false;
                m_wr = 0;
                m_next_seq = 1;
                m_step = STEP_ERASE;
            }
            break;
        default:
            break;
    }
    m_op = OP_NONE;
    m_busy = false;
}

static void fs_setup(void) {
    logring_view_t v;

    ret_code_t irc = nrf_fstorage_init(&m_logflash_fs, &nrf_fstorage_sd, NULL);
    if (irc != NRF_SUCCESS) {
        set_err(3, irc);
        m_failed = true;
        return;
    }
    logring_scan(&v);
    if (v.count == 0) {
        m_wr = 0;
        m_next_seq = 1;
        m_step = STEP_ERASE;
    } else {
        uint32_t newest = (v.first + v.count - 1u) % LOGRING_PAGES;
        uint32_t used = v.length - (v.count - 1u) * LOGRING_PAGE_DATA;
        m_next_seq = v.newest_seq + 1u;
        if (used >= LOGRING_PAGE_DATA) {
            m_wr = ((newest + 1u) % LOGRING_PAGES) * LOGRING_PAGE_SIZE;
            m_step = STEP_ERASE;
        } else {
            m_wr = newest * LOGRING_PAGE_SIZE + LOGRING_HDR_SIZE + used;
            m_step = STEP_DATA;
        }
    }
    m_fs_ready = true;
}

/* Issue one flash operation; mark busy first, the event may arrive at once. */
static void issue(op_t op, ret_code_t (*fn)(void)) {
    m_op = op;
    m_busy = true;
    ret_code_t rc = fn();
    if (rc != NRF_SUCCESS) {
        m_op = OP_NONE;
        m_busy = false;
        if (rc != NRF_ERROR_NO_MEM && rc != NRF_ERROR_BUSY) {
            m_op = op;
            set_err(1, rc);
            m_op = OP_NONE;
            m_failed = true;
        }
    }
}

static ret_code_t do_erase_ring_page(void) {
    return nrf_fstorage_erase(&m_logflash_fs, LOGRING_BASE + (m_wr / LOGRING_PAGE_SIZE) * LOGRING_PAGE_SIZE, 1, NULL);
}

static ret_code_t do_clear_page(void) {
    return nrf_fstorage_erase(&m_logflash_fs, LOGRING_BASE + m_clear_page * LOGRING_PAGE_SIZE, 1, NULL);
}

static ret_code_t do_write_hdr(void) {
    m_hdr.magic = LOGRING_MAGIC;
    m_hdr.seq = m_next_seq;
    return nrf_fstorage_write(&m_logflash_fs, LOGRING_BASE + m_wr, &m_hdr, sizeof(m_hdr), NULL);
}

static ret_code_t do_write_data(void) {
    uint32_t idx = m_ram.flushed & (LF_RAM_SIZE - 1);
    return nrf_fstorage_write(&m_logflash_fs, LOGRING_BASE + m_wr, &m_ram.buf[idx], m_inflight, NULL);
}

void logflash_request_flush(void) {
    m_force = true;
}

void logflash_poll(void) {
    if (!m_fs_ready) {
        if (m_failed || !nrf_sdh_is_enabled()) {
            return;
        }
        fs_setup();
        if (!m_fs_ready) {
            return;
        }
    }
    if (m_busy || m_failed) {
        return;
    }

    if (m_clear_req) {
        issue(OP_CLEAR, do_clear_page);
        return;
    }

    uint32_t pend = m_ram.head - m_ram.flushed;

    /* RAM state damaged: restart the RAM ring rather than issue bad writes */
    if (pend > LF_RAM_SIZE || (m_ram.flushed & 3)) {
        m_ram.head = 0;
        m_ram.flushed = 0;
        return;
    }

    /* flash writes are whole words: pad a short tail once the log goes quiet */
    if ((pend & 3) &&
        (m_force || app_timer_cnt_diff_compute(app_timer_cnt_get(), m_last_append) >= APP_TIMER_TICKS(LF_IDLE_FLUSH_MS))) {
        ram_put("\n\n\n", 4 - (pend & 3));
        pend = m_ram.head - m_ram.flushed;
    }
    if (pend < 4) {
        m_force = false;
        return;
    }

    switch (m_step) {
        case STEP_ERASE:
            issue(OP_ERASE, do_erase_ring_page);
            break;
        case STEP_HDR:
            issue(OP_HDR, do_write_hdr);
            break;
        case STEP_DATA: {
            uint32_t idx = m_ram.flushed & (LF_RAM_SIZE - 1);
            uint32_t n = pend & ~3u;
            if (n > LF_RAM_SIZE - idx)                           n = LF_RAM_SIZE - idx;
            if (n > LOGRING_PAGE_SIZE - (m_wr % LOGRING_PAGE_SIZE)) n = LOGRING_PAGE_SIZE - (m_wr % LOGRING_PAGE_SIZE);
            if (n > LF_CHUNK_MAX)                                n = LF_CHUNK_MAX;
            m_inflight = n;
            issue(OP_DATA, do_write_data);
            break;
        }
    }
}

void logflash_flush_blocking(uint32_t timeout_ms) {
    NRF_LOG_FLUSH();
    m_force = true;
    for (uint32_t t = 0; t < timeout_ms * 5u; t++) {
        logflash_poll();
        if (!m_busy && m_ram.head == m_ram.flushed) {
            break;
        }
        nrf_delay_us(200);
    }
}

/* ---- host access ------------------------------------------------------- */

void logflash_get_stats(logflash_stats_t *out) {
    logring_view_t v;
    logring_scan(&v);
    out->level   = m_level;
    out->failed  = m_failed;
    out->stored  = v.length;
    out->pending = m_ram.head - m_ram.flushed;
    out->dropped = m_dropped;
    out->boots   = m_ram.boots;
    out->err     = m_err;
}

uint32_t logflash_read(uint32_t offset, uint8_t *dst, uint32_t len) {
    logring_view_t v;
    logring_scan(&v);
    return logring_read(&v, offset, dst, len);
}

void logflash_wipe_noinit(uint32_t base, uint32_t size) {
    uint32_t keep_lo = (uint32_t)&m_ram;
    uint32_t keep_hi = keep_lo + sizeof(m_ram);

    for (uint32_t a = base; a < base + size; a += 4) {
        if (a < keep_lo || a >= keep_hi) {
            *(volatile uint32_t *)a = 0xFFFFFFFFu;
        }
    }
}

void logflash_clear(void) {
    m_failed = false;
    m_err = 0;
    m_clear_page = 0;
    m_clear_req = true;
}
