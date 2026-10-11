#include "gdb_rsp.h"

#include <string.h>

#include "bsp_wdt.h"
#include "nrf_delay.h"
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "usb_main.h"

#define NRF_LOG_MODULE_NAME gdbrsp
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

/* Advertised GDB PacketSize (hex). Keeps the RX/TX buffers small; gdb chunks
 * larger transfers to fit. */
#define GDB_PACKET_SIZE   0x200u   /* advertised; gdb chunks larger transfers */
#define GDB_PKT_MAX       600u     /* payload between $ and # (binary writes) */
#define GDB_OUT_MAX       600u
#define GDB_MEM_READ_MAX  256u     /* bytes per 'm' (-> 512 hex chars) */

#define FLASH_PAGE        4096u
#define FLASH_SPAN_END    0x00100000u
#define FS_WAIT_US        5000000u

/* Flash writes are confined to [SAFE_FLASH_MIN, SAFE_FLASH_MAX): the FDS area,
 * bootloader region and settings/param pages. Everything below 0xC7000 (MBR,
 * SoftDevice and the RUNNING application) is refused -- programming the live
 * app from the app crashes mid-write, and touching the MBR/SD corrupts the
 * stack. Reads are unrestricted; only vFlashErase/Write are gated. Use UF2/DFU
 * to replace the app itself. (Flash map: app 0x27000-0xC7000, FDS 0xC7000-
 * 0xF3000, BL 0xF3000-0xFE000, MBR params 0xFE000, settings 0xFF000.) */
#define SAFE_FLASH_MIN    0x000C7000u
#define SAFE_FLASH_MAX    0x00100000u

static bool m_active;

/* ---- RSP receive state machine -------------------------------------- */
enum { ST_IDLE, ST_DATA, ST_CSUM1, ST_CSUM2 };
static uint8_t  m_state;
static uint8_t  m_pkt[GDB_PKT_MAX];
static uint16_t m_pkt_len;
static uint8_t  m_csum;
static uint8_t  m_csum_rx;

static char     m_out[GDB_OUT_MAX];
static bool     m_ack_pending;   /* prepend '+' to the next packet we send */

/* ---- flash backend (SoftDevice fstorage, synchronous) --------------- */
static void fs_evt(nrf_fstorage_evt_t *p_evt);
NRF_FSTORAGE_DEF(nrf_fstorage_t m_gdb_fs) = {
    .evt_handler = fs_evt,
    .start_addr  = 0x00000000u,
    .end_addr    = FLASH_SPAN_END,   /* exclusive end, matches the SDK convention */
};
static volatile bool       m_fs_done;
static volatile ret_code_t m_fs_res;
static bool                m_fs_inited;

/* Flash write stream: no full-page RAM buffer. Bytes are combined into a tiny
 * word-aligned buffer and written out in whole words, erasing each page lazily
 * the first time the cursor enters it. Keeps the mode's RAM footprint small so
 * it coexists with the other standalone modes. */
#define WR_BUF            64u      /* multiple of 4 */
static uint32_t m_fl_buf32[WR_BUF / 4];
#define m_fl_buf  ((uint8_t *)m_fl_buf32)
static uint32_t m_fl_waddr;        /* word-aligned flash write cursor */
static uint32_t m_fl_next;         /* next incoming byte address expected */
static uint16_t m_fl_len;          /* bytes buffered, starting at m_fl_waddr */
static uint32_t m_fl_erased;       /* last page erased (0xFFFFFFFF = none) */
static bool     m_fl_open;         /* a write region is in progress */

static void fs_evt(nrf_fstorage_evt_t *p_evt) {
    m_fs_res = p_evt->result;
    m_fs_done = true;
}

static bool fs_wait(void) {
    for (uint32_t t = 0; !m_fs_done; t += 100) {
        if (t >= FS_WAIT_US) {
            return false;
        }
        bsp_wdt_feed();
        nrf_delay_us(100);
    }
    return m_fs_res == NRF_SUCCESS;
}

static bool fs_init(void) {
    if (m_fs_inited) {
        return true;
    }
    if (nrf_fstorage_init(&m_gdb_fs, &nrf_fstorage_sd, NULL) != NRF_SUCCESS) {
        return false;
    }
    m_fs_inited = true;
    return true;
}

/* True only if [addr, addr+len) lies entirely in the writable flash window. */
static bool flash_region_ok(uint32_t addr, uint32_t len) {
    if (len == 0) {
        return true;
    }
    uint32_t a_end = addr + len;
    if (a_end < addr) {
        return false;   /* wrap */
    }
    return addr >= SAFE_FLASH_MIN && a_end <= SAFE_FLASH_MAX;
}

/* ---- small hex helpers ---------------------------------------------- */
static const char HEXD[] = "0123456789abcdef";

static int hexval(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse a hex integer, advancing *pp. Returns the number of digits consumed. */
static int parse_hex(const char **pp, const char *end, uint32_t *out) {
    uint32_t v = 0;
    int n = 0;
    const char *p = *pp;
    while (p < end) {
        int d = hexval((uint8_t)*p);
        if (d < 0) break;
        v = (v << 4) | (uint32_t)d;
        p++;
        n++;
    }
    *pp = p;
    *out = v;
    return n;
}

/* ---- packet output --------------------------------------------------- */
static void send_raw(const char *s, uint16_t len) {
    usb_cdc_write(s, len);
}

/* Frame and send m_out[0..len): "$<payload>#<csum>". */
static void send_payload(const char *payload, uint16_t len) {
    static char frame[GDB_OUT_MAX + 8];
    uint8_t cs = 0;
    uint16_t j = 0;
    /* Fold the packet ack into this transmission: one usb_cdc_write per
     * request avoids a second write hitting NRF_ERROR_BUSY before TX_DONE. */
    if (m_ack_pending) {
        frame[j++] = '+';
        m_ack_pending = false;
    }
    frame[j++] = '$';
    for (uint16_t i = 0; i < len && j < sizeof(frame) - 4; i++) {
        frame[j++] = payload[i];
        cs += (uint8_t)payload[i];
    }
    frame[j++] = '#';
    frame[j++] = HEXD[(cs >> 4) & 0xF];
    frame[j++] = HEXD[cs & 0xF];
    send_raw(frame, j);
}

static void send_str(const char *s) {
    send_payload(s, (uint16_t)strlen(s));
}

static void send_ok(void)    { send_str("OK"); }
static void send_empty(void) { send_payload("", 0); }
static void send_err(uint8_t e) {
    char b[4] = { 'E', HEXD[(e >> 4) & 0xF], HEXD[e & 0xF], 0 };
    send_str(b);
}

/* ---- qXfer static-document responder -------------------------------- */
/* Minimal Cortex-M target description so `g`/`p` have a defined layout. */
static const char TARGET_XML[] =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
    "<target version=\"1.0\">"
    "<architecture>armv7e-m</architecture>"
    "<feature name=\"org.gnu.gdb.arm.m-profile\">"
    "<reg name=\"r0\" bitsize=\"32\"/>"
    "<reg name=\"r1\" bitsize=\"32\"/>"
    "<reg name=\"r2\" bitsize=\"32\"/>"
    "<reg name=\"r3\" bitsize=\"32\"/>"
    "<reg name=\"r4\" bitsize=\"32\"/>"
    "<reg name=\"r5\" bitsize=\"32\"/>"
    "<reg name=\"r6\" bitsize=\"32\"/>"
    "<reg name=\"r7\" bitsize=\"32\"/>"
    "<reg name=\"r8\" bitsize=\"32\"/>"
    "<reg name=\"r9\" bitsize=\"32\"/>"
    "<reg name=\"r10\" bitsize=\"32\"/>"
    "<reg name=\"r11\" bitsize=\"32\"/>"
    "<reg name=\"r12\" bitsize=\"32\"/>"
    "<reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/>"
    "<reg name=\"lr\" bitsize=\"32\"/>"
    "<reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/>"
    "<reg name=\"xpsr\" bitsize=\"32\" regnum=\"25\"/>"
    "</feature></target>";

/* The whole 1 MB is 4 KB-page flash except the RAM window; gdb `load` uses
 * vFlash for flash addresses and M for RAM. */
static const char MEMORY_MAP_XML[] =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\""
    " \"http://sourceware.org/gdb/gdb-memory-map.dtd\">"
    "<memory-map>"
    "<memory type=\"flash\" start=\"0x0\" length=\"0x100000\">"
    "<property name=\"blocksize\">0x1000</property></memory>"
    "<memory type=\"ram\" start=\"0x20000000\" length=\"0x40000\"/>"
    "</memory-map>";

/* Serve a static document for a qXfer:...:read request given offset,len. */
static void send_qxfer(const char *doc, uint32_t off, uint32_t len) {
    uint32_t total = (uint32_t)strlen(doc);
    if (off >= total) {
        send_str("l");               /* nothing left */
        return;
    }
    uint32_t n = total - off;
    if (n > len) {
        n = len;
    }
    if (n > GDB_OUT_MAX - 1) {
        n = GDB_OUT_MAX - 1;
    }
    m_out[0] = (off + n < total) ? 'm' : 'l';
    memcpy(&m_out[1], doc + off, n);
    send_payload(m_out, (uint16_t)(n + 1));
}

/* Parse a trailing "OFF,LEN" from a qXfer request (after the last ':'). */
static bool parse_qxfer_tail(const char *p, const char *end, uint32_t *off, uint32_t *len) {
    const char *q = p;
    if (!parse_hex(&q, end, off)) return false;
    if (q >= end || *q != ',') return false;
    q++;
    if (!parse_hex(&q, end, len)) return false;
    return true;
}

/* ---- memory ---------------------------------------------------------- */
static void do_mem_read(const char *p, const char *end) {
    uint32_t addr, len;
    if (!parse_hex(&p, end, &addr) || p >= end || *p != ',') { send_err(0x16); return; }
    p++;
    if (!parse_hex(&p, end, &len)) { send_err(0x16); return; }
    if (len > GDB_MEM_READ_MAX) len = GDB_MEM_READ_MAX;
    const volatile uint8_t *src = (const volatile uint8_t *)addr;
    uint16_t j = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint8_t b = src[i];
        m_out[j++] = HEXD[(b >> 4) & 0xF];
        m_out[j++] = HEXD[b & 0xF];
    }
    send_payload(m_out, j);
}

static void do_mem_write(const char *p, const char *end) {
    uint32_t addr, len;
    if (!parse_hex(&p, end, &addr) || p >= end || *p != ',') { send_err(0x16); return; }
    p++;
    if (!parse_hex(&p, end, &len) || p >= end || *p != ':') { send_err(0x16); return; }
    p++;
    volatile uint8_t *dst = (volatile uint8_t *)addr;
    for (uint32_t i = 0; i < len; i++) {
        if (p + 1 >= end) { send_err(0x16); return; }
        int hi = hexval((uint8_t)p[0]);
        int lo = hexval((uint8_t)p[1]);
        if (hi < 0 || lo < 0) { send_err(0x16); return; }
        dst[i] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    send_ok();
}

/* ---- flash ----------------------------------------------------------- */
static bool fl_erase(uint32_t page) {
    if (page == m_fl_erased) {
        return true;
    }
    m_fs_done = false;
    if (nrf_fstorage_erase(&m_gdb_fs, page, 1, NULL) != NRF_SUCCESS || !fs_wait()) {
        return false;
    }
    m_fl_erased = page;
    return true;
}

/* Write the whole words held in m_fl_buf, erasing pages lazily and never
 * crossing a page boundary in one write. On `final`, a trailing partial word
 * is padded with 0xFF. Any sub-word tail is kept at the front for next time. */
static bool fl_flush(bool final) {
    if (final) {
        while (m_fl_len & 3u) {
            m_fl_buf[m_fl_len++] = 0xFF;
        }
    }
    uint16_t full = m_fl_len & ~3u;
    uint16_t done = 0;
    while (done < full) {
        uint32_t page = m_fl_waddr & ~(FLASH_PAGE - 1u);
        if (!fl_erase(page)) {
            return false;
        }
        uint32_t page_left = FLASH_PAGE - (m_fl_waddr - page);   /* multiple of 4 */
        uint32_t n = full - done;
        if (n > page_left) {
            n = page_left;
        }
        m_fs_done = false;
        if (nrf_fstorage_write(&m_gdb_fs, m_fl_waddr, &m_fl_buf[done], n, NULL) != NRF_SUCCESS ||
                !fs_wait()) {
            return false;
        }
        m_fl_waddr += n;
        done += n;
    }
    uint16_t tail = m_fl_len - full;
    for (uint16_t i = 0; i < tail; i++) {
        m_fl_buf[i] = m_fl_buf[full + i];
    }
    m_fl_len = tail;
    return true;
}

static void fl_reset(void) {
    m_fl_open = false;
    m_fl_len = 0;
    m_fl_erased = 0xFFFFFFFFu;
}

/* Stream `len` bytes for ascending flash address `addr`. */
static bool fl_write(uint32_t addr, const uint8_t *data, uint32_t len) {
    if (!m_fl_open || addr != m_fl_next) {
        if (!fl_flush(true)) {          /* finish any previous region first */
            return false;
        }
        m_fl_waddr = addr & ~3u;
        m_fl_len = (uint16_t)(addr & 3u);          /* unknown low bytes stay 0xFF */
        for (uint16_t i = 0; i < m_fl_len; i++) {
            m_fl_buf[i] = 0xFF;
        }
        m_fl_next = addr;
        m_fl_open = true;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (m_fl_len == WR_BUF) {
            if (!fl_flush(false)) {
                return false;
            }
        }
        m_fl_buf[m_fl_len++] = data[i];
        m_fl_next++;
    }
    return true;
}

static void do_vflash_erase(const char *p, const char *end) {
    /* "vFlashErase:addr,length". Validate the range and refuse any erase
     * outside the writable window, so a `load` over the running app fails
     * cleanly (gdb aborts) instead of crashing. Pages are erased lazily in
     * fl_flush, just before each word is written. */
    uint32_t addr, len;
    if (!parse_hex(&p, end, &addr) || p >= end || *p != ',') { send_err(0x16); return; }
    p++;
    if (!parse_hex(&p, end, &len)) { send_err(0x16); return; }
    if (!flash_region_ok(addr, len)) { send_err(0x02); return; }
    if (!fs_init()) { send_err(0x01); return; }
    fl_reset();      /* gdb erases before writing; start a fresh stream */
    send_ok();
}

static void do_vflash_write(const char *p, const char *end) {
    /* payload: "addr:<binary>" (binary already un-escaped by the caller). */
    uint32_t addr;
    if (!parse_hex(&p, end, &addr) || p >= end || *p != ':') { send_err(0x16); return; }
    p++;
    if (!flash_region_ok(addr, (uint32_t)(end - p))) { send_err(0x02); return; }
    if (!fs_init()) { send_err(0x01); return; }
    if (!fl_write(addr, (const uint8_t *)p, (uint32_t)(end - p))) { send_err(0x01); return; }
    send_ok();
}

static void do_vflash_done(void) {
    if (!fl_flush(true)) { send_err(0x01); return; }
    fl_reset();
    send_ok();
}

/* Un-escape a GDB binary payload in place (0x7d escape: next byte ^ 0x20).
 * Returns the new length. */
static uint16_t unescape(uint8_t *buf, uint16_t len) {
    uint16_t r = 0, w = 0;
    while (r < len) {
        uint8_t c = buf[r++];
        if (c == 0x7d && r < len) {
            c = buf[r++] ^ 0x20;
        }
        buf[w++] = c;
    }
    return w;
}

/* ---- packet dispatch ------------------------------------------------- */
static bool str_pref(const char *s, uint16_t len, const char *pref) {
    uint16_t n = (uint16_t)strlen(pref);
    return len >= n && memcmp(s, pref, n) == 0;
}

static void dispatch(uint8_t *pkt, uint16_t len) {
    if (len == 0) {
        send_empty();
        return;
    }
    const char *s = (const char *)pkt;
    const char *end = s + len;
    char c = s[0];

    switch (c) {
        case '?':
            send_str("S05");   /* benign "stopped (TRAP)" so gdb attaches */
            return;
        case 'g': {            /* read all registers: 17 x 32-bit, zeroed */
            uint16_t j = 0;
            for (int i = 0; i < 17 * 8; i++) m_out[j++] = '0';
            send_payload(m_out, j);
            return;
        }
        case 'G':
            send_ok();
            return;
        case 'p': {            /* read one register -> 0 */
            memcpy(m_out, "00000000", 8);
            send_payload(m_out, 8);
            return;
        }
        case 'P':
        case 'H':
            send_ok();
            return;
        case 'm':
            do_mem_read(s + 1, end);
            return;
        case 'M':
            do_mem_write(s + 1, end);
            return;
        case 'c': case 's': case 'C': case 'S':
            /* No execution control; report immediately "stopped". */
            send_str("S05");
            return;
        case 'D':
            /* Detach: gdb is leaving, but the mode stays armed so it can
             * reconnect. Disarm via the both-button long press. */
            fl_flush(true);
            fl_reset();
            send_ok();
            return;
        case 'k':
            /* Kill/quit: no reply; stay armed, flush any pending bytes. */
            fl_flush(true);
            fl_reset();
            return;
        case 'R':
            send_ok();
            return;
        case 'z': case 'Z':
            send_empty();       /* no breakpoint/watchpoint support */
            return;
        case 'q':
            if (str_pref(s, len, "qSupported")) {
                send_str("PacketSize=200;qXfer:memory-map:read+;qXfer:features:read+");
                return;
            }
            if (str_pref(s, len, "qXfer:memory-map:read::")) {
                uint32_t off, l;
                const char *p = s + strlen("qXfer:memory-map:read::");
                if (parse_qxfer_tail(p, end, &off, &l)) send_qxfer(MEMORY_MAP_XML, off, l);
                else send_err(0x16);
                return;
            }
            if (str_pref(s, len, "qXfer:features:read:")) {
                /* ...:features:read:<annex>:off,len - skip the annex field */
                const char *p = s + strlen("qXfer:features:read:");
                while (p < end && *p != ':') p++;
                if (p < end) p++;
                uint32_t off, l;
                if (parse_qxfer_tail(p, end, &off, &l)) send_qxfer(TARGET_XML, off, l);
                else send_err(0x16);
                return;
            }
            if (str_pref(s, len, "qAttached")) { send_str("1"); return; }
            if (str_pref(s, len, "qfThreadInfo")) { send_str("m0"); return; }
            if (str_pref(s, len, "qsThreadInfo")) { send_str("l"); return; }
            if (str_pref(s, len, "qC")) { send_str("QC0"); return; }
            send_empty();
            return;
        case 'v':
            if (str_pref(s, len, "vMustReplyEmpty")) { send_empty(); return; }
            if (str_pref(s, len, "vFlashErase:")) {
                do_vflash_erase(s + strlen("vFlashErase:"), end);
                return;
            }
            if (str_pref(s, len, "vFlashWrite:")) {
                /* un-escape the binary portion (after "vFlashWrite:") in place */
                uint16_t pref = (uint16_t)strlen("vFlashWrite:");
                uint16_t nlen = unescape(pkt + pref, (uint16_t)(len - pref));
                do_vflash_write((const char *)pkt + pref, (const char *)pkt + pref + nlen);
                return;
            }
            if (str_pref(s, len, "vFlashDone")) { do_vflash_done(); return; }
            send_empty();       /* vCont?, vRun, etc. */
            return;
        default:
            send_empty();
            return;
    }
}

/* ---- byte-level receive --------------------------------------------- */
void gdb_rsp_rx(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = data[i];

        if (m_state == ST_IDLE) {
            if (ch == '$') {
                m_state = ST_DATA;
                m_pkt_len = 0;
                m_csum = 0;
            } else if (ch == 0x03) {
                send_str("S05");    /* Ctrl-C interrupt */
            }
            /* '+'/'-' acks and stray bytes are ignored between packets */
            continue;
        }

        if (m_state == ST_DATA) {
            if (ch == '#') {
                m_state = ST_CSUM1;
            } else if (m_pkt_len < GDB_PKT_MAX) {
                m_pkt[m_pkt_len++] = ch;
                m_csum += ch;
            } else {
                /* overflow: abandon this packet */
                m_state = ST_IDLE;
            }
            continue;
        }

        if (m_state == ST_CSUM1) {
            int d = hexval(ch);
            m_csum_rx = (d < 0) ? 0 : (uint8_t)(d << 4);
            m_state = ST_CSUM2;
            continue;
        }

        if (m_state == ST_CSUM2) {
            int d = hexval(ch);
            if (d >= 0) m_csum_rx |= (uint8_t)d;
            m_state = ST_IDLE;
            if (m_csum_rx == m_csum) {
                m_ack_pending = true;       /* ack is folded into the reply */
                dispatch(m_pkt, m_pkt_len);
            } else {
                send_raw("-", 1);           /* nak: ask gdb to resend */
            }
        }
    }
}

void gdb_rsp_enter(void) {
    m_state = ST_IDLE;
    m_pkt_len = 0;
    m_ack_pending = false;
    fl_reset();
    m_active = true;
    NRF_LOG_INFO("GDB RSP gateway active on CDC");
}

void gdb_rsp_leave(void) {
    fl_flush(true);         /* commit any buffered bytes before leaving */
    fl_reset();
    m_active = false;
    NRF_LOG_INFO("GDB RSP gateway stopped");
}

bool gdb_rsp_active(void) {
    return m_active;
}
