#include "lf_ia_trace.h"

#include <string.h>

#include "app_util_platform.h"

// The trace lives in the retained noinit region, so it survives System OFF (the CU sleeps when the reader's field
// drops) and the reset that USB wake causes. A tester can take the CU to a reader on battery and read the trace back
// after reconnecting. This reuses the same retention the MIFARE logs and the field probe use: the .noinit region
// (noinit.ld), RAM8 retention set in app_main, and the first-power wipe to 0xFF in check_wakeup_src. The wipe makes
// the header below invalid, so the store is reset on the next use, like the MIFARE log's count guard. The magic,
// version and record size reject a layout left by an earlier flash, which the count-only guard would not catch.
#define LF_IA_TRACE_MAGIC   (0x32414C46u)  // "FLA2": interactive LF trace, layout 2
#define LF_IA_TRACE_VERSION (2u)
#define LF_IA_TRACE_ROLL    (LF_IA_TRACE_RECORDS - LF_IA_TRACE_KEEP)

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t rec_size;  // sizeof(lf_ia_trace_rec_t), so a changed record layout is rejected
    uint32_t written;   // records committed since the last clear, which may exceed LF_IA_TRACE_RECORDS
    uint16_t boot;      // boots that used the trace since the last clear
    uint16_t session_records;  // records in the current field session
    uint32_t session_t_us;     // when the current field session started
    lf_ia_stats_t stats;
    lf_ia_trace_rec_t recs[LF_IA_TRACE_RECORDS];
} lf_ia_trace_store_t;

static __attribute__((section(".noinit_lfia"))) lf_ia_trace_store_t m_store;

// The record being filled, from begin to commit. One field session at a time, so a plain pointer, zeroed at boot: an
// open record left by a reset is simply dropped.
static lf_ia_trace_rec_t *m_open;
// Whether this boot has been counted. Zeroed at boot, unlike the store.
static bool m_boot_counted;

static bool store_valid(void) {
    return m_store.magic == LF_IA_TRACE_MAGIC && m_store.version == LF_IA_TRACE_VERSION &&
           m_store.rec_size == sizeof(lf_ia_trace_rec_t);
}

// Starts a fresh store in place if the header is not this layout's, and counts this boot the first time the store is
// used after it. Callers that can race the engine's interrupt writes hold a critical region around this.
static void store_ensure(void) {
    if (!store_valid()) {
        memset(&m_store, 0, sizeof(m_store));
        m_store.magic = LF_IA_TRACE_MAGIC;
        m_store.version = LF_IA_TRACE_VERSION;
        m_store.rec_size = sizeof(lf_ia_trace_rec_t);
    }
    if (!m_boot_counted) {
        m_boot_counted = true;
        m_store.boot++;
    }
}

// The slot of record k (counted since the clear): the first LF_IA_TRACE_KEEP stay, the rest roll.
static lf_ia_trace_rec_t *slot_of(uint32_t k) {
    const uint32_t i = k < LF_IA_TRACE_KEEP ? k : LF_IA_TRACE_KEEP + (k - LF_IA_TRACE_KEEP) % LF_IA_TRACE_ROLL;
    return &m_store.recs[i];
}

void lf_ia_trace_session_start(uint32_t t_us) {
    store_ensure();
    m_store.stats.sessions++;
    m_store.session_records = 0;
    m_store.session_t_us = t_us;
}

lf_ia_trace_rec_t *lf_ia_trace_session_end(uint32_t t_us, uint16_t level) {
    store_ensure();
    if (m_store.session_records == 0) {
        return NULL;
    }
    lf_ia_trace_rec_t *r = lf_ia_trace_begin(LF_IA_TR_FIELD_OFF);
    r->t_us = t_us;
    r->level = level;
    lf_ia_trace_commit();
    return r;
}

lf_ia_trace_rec_t *lf_ia_trace_begin(uint8_t type) {
    store_ensure();
    m_open = slot_of(m_store.written);
    memset(m_open, 0, sizeof(*m_open));
    m_open->type = type;
    m_open->boot = m_store.boot;
    m_open->session = (uint16_t)m_store.stats.sessions;
    m_open->t_session_us = m_store.session_t_us;
    return m_open;
}

void lf_ia_trace_commit(void) {
    if (m_open) {
        m_open = NULL;
        m_store.written++;
        m_store.session_records++;
    }
}

lf_ia_trace_rec_t *lf_ia_trace_last(void) {
    if (!store_valid() || m_store.written == 0) {
        return NULL;
    }
    return slot_of(m_store.written - 1);
}

lf_ia_stats_t *lf_ia_trace_stats(void) {
    store_ensure();
    return &m_store.stats;
}

void lf_ia_trace_clear(void) {
    CRITICAL_REGION_ENTER();
    // A clear restarts the store, so this boot counts as boot 1.
    m_store.magic = 0;
    m_boot_counted = false;
    store_ensure();
    m_open = NULL;
    CRITICAL_REGION_EXIT();
}

size_t lf_ia_trace_read(size_t first, lf_ia_trace_rec_t *out, size_t max, uint32_t *total_out, uint16_t *boot_out) {
    size_t n = 0;
    CRITICAL_REGION_ENTER();
    store_ensure();
    const uint32_t w = m_store.written;
    const uint32_t kept = w < LF_IA_TRACE_RECORDS ? w : LF_IA_TRACE_RECORDS;
    for (size_t i = first; i < kept && n < max; i++, n++) {
        // Index i is record i while nothing is lost. After that, the kept first records come first, then the newest
        // LF_IA_TRACE_ROLL records in order.
        const uint32_t k = (w <= LF_IA_TRACE_RECORDS || i < LF_IA_TRACE_KEEP) ? i : w - (kept - i);
        out[n] = *slot_of(k);
    }
    *total_out = w;
    *boot_out = m_store.boot;
    CRITICAL_REGION_EXIT();
    return n;
}
