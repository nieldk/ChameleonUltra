#include "gdb_rsp.h"

#include <stdio.h>
#include <string.h>

#include "bsp_wdt.h"
#include "ble_main.h"
#include "delayed_reset.h"
#include "nrf_delay.h"
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "usb_main.h"

#define NRF_LOG_MODULE_NAME gdbrsp
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

/* Advertised GDB PacketSize and the RX/TX buffers derived from it. Bigger means
 * fewer round-trips on bulk reads (find/dump) but more RAM; set with the
 * GDB_GATEWAY_PKT build flag. Default 0x200 keeps the mode RAM-slim for
 * multi-mode builds; 0x800 roughly quarters a full-chip dump's round-trips. */
#ifndef CONFIG_GDB_GATEWAY_PKT
#define CONFIG_GDB_GATEWAY_PKT  0x200u
#endif
#define GDB_PACKET_SIZE   (CONFIG_GDB_GATEWAY_PKT)
#define GDB_PKT_MAX       (GDB_PACKET_SIZE + 88u)   /* $..# payload (binary writes) */
#define GDB_OUT_MAX       (GDB_PACKET_SIZE + 88u)   /* outgoing payload (hex reply, qXfer) */
#define GDB_MEM_READ_MAX  (GDB_PACKET_SIZE / 2u)    /* 2 hex chars/byte -> reply fits PacketSize */

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
#define APP_FLASH_BASE    0x00027000u   /* app image start; MBR+SD sit below */

static bool m_active;

/* Lower bound of the writable flash window. Default (SAFE_FLASH_MIN) protects
 * MBR, SoftDevice and the running app; `monitor unlock-app` lowers it to the
 * app base for targeted patches. Re-armed to the default on every arm. */
static uint32_t m_wr_min = SAFE_FLASH_MIN;

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
    return addr >= m_wr_min && a_end <= SAFE_FLASH_MAX;
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
/* Same link-selection as app_cmd.c's auto_response_data: reply on whichever
 * transport is actually up, USB preferred. Lets the gateway work unmodified
 * whether gdb attaches over USB-CDC or BLE NUS. */
static void send_raw(const char *s, uint16_t len) {
    if (is_usb_working()) {
        usb_cdc_write(s, len);
    } else if (is_nus_working()) {
        nus_data_response((uint8_t *)s, len);
    }
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

#if CONFIG_GDB_GATEWAY_EXEC
/* Emit just the packet ack, for commands that send no response packet now
 * (continue/step: the stop reply comes later). Keeps gdb from retransmitting. */
static void send_ack(void) {
    if (m_ack_pending) {
        send_raw("+", 1);
        m_ack_pending = false;
    }
}
#endif

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
    bsp_wdt_feed();   /* a long find/dump floods reads; keep the WDT fed so the
                         scan can't reset the device out from under gdb */
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

/* =====================================================================
 * Execution control (monitor-mode debug) -- optional, CONFIG_GDB_GATEWAY_EXEC.
 *
 * Breakpoints (FPB, up to 6), watchpoints (DWT, up to 4) and continue via the
 * Cortex-M DebugMonitor exception. No SWD: debug events trap to
 * DebugMon_Handler, which parks in a loop servicing gdb over the same CDC link
 * while higher-priority interrupts (USB, SoftDevice) keep running. Hardware
 * single-step is deliberately NOT offered -- resuming for one instruction lets
 * those interrupts escape the step and drop the link; gdb steps in software
 * (temp breakpoints + continue) instead, over this same breakpoint path.
 * ===================================================================== */
#if CONFIG_GDB_GATEWAY_EXEC

#include "app_usbd.h"
#include "nrf.h"

extern volatile bool g_usb_port_opened;   /* CDC DTR: false once gdb closes the port */

#define FP_CTRL_REG      (*(volatile uint32_t *)0xE0002000u)
#define FP_COMP_REG(n)   (*(volatile uint32_t *)(0xE0002008u + 4u * (uint32_t)(n)))
#define DWT_COMP_REG(n)  (*(volatile uint32_t *)(0xE0001020u + 16u * (uint32_t)(n)))
#define DWT_MASK_REG(n)  (*(volatile uint32_t *)(0xE0001024u + 16u * (uint32_t)(n)))
#define DWT_FUNC_REG(n)  (*(volatile uint32_t *)(0xE0001028u + 16u * (uint32_t)(n)))
#define GDB_MAX_HWBP     6u
#define GDB_MAX_WP       4u

static volatile bool    m_halted;   /* true while stopped in the DebugMon loop */
static volatile uint8_t m_run;      /* leave the loop: 1 = continue             */
static uint32_t         m_regs[17]; /* r0-r15, xPSR captured on halt            */
static uint8_t          m_ncode;    /* usable FPB code comparators              */

/* register <-> hex in little-endian (target) byte order */
static void word_le_hex(char *o, uint32_t v) {
    for (int b = 0; b < 4; b++) {
        uint8_t byte = (v >> (b * 8)) & 0xFFu;
        o[b * 2]     = HEXD[byte >> 4];
        o[b * 2 + 1] = HEXD[byte & 0xF];
    }
}
static uint32_t hex_le_word(const char *p) {
    uint32_t v = 0;
    for (int b = 0; b < 4; b++) {
        int hi = hexval((uint8_t)p[b * 2]);
        int lo = hexval((uint8_t)p[b * 2 + 1]);
        if (hi < 0 || lo < 0) break;
        v |= (uint32_t)((hi << 4) | lo) << (b * 8);
    }
    return v;
}

static void fpb_enable(void) {
    m_ncode = (uint8_t)((((FP_CTRL_REG >> 12) & 0x7u) << 4) | ((FP_CTRL_REG >> 4) & 0xFu));
    if (m_ncode == 0 || m_ncode > GDB_MAX_HWBP) {
        m_ncode = GDB_MAX_HWBP;
    }
    FP_CTRL_REG = (1u << 1) | (1u << 0);   /* KEY | ENABLE */
}
static bool fpb_set(uint32_t addr) {
    for (uint8_t i = 0; i < m_ncode; i++) {
        if (FP_COMP_REG(i) & 1u) {
            continue;
        }
        uint32_t replace = (addr & 2u) ? 2u : 1u;   /* upper / lower halfword */
        FP_COMP_REG(i) = (replace << 30) | (addr & 0x1FFFFFFCu) | 1u;
        return true;
    }
    return false;
}
static bool fpb_clear(uint32_t addr) {
    for (uint8_t i = 0; i < m_ncode; i++) {
        if ((FP_COMP_REG(i) & 1u) &&
                (FP_COMP_REG(i) & 0x1FFFFFFCu) == (addr & 0x1FFFFFFCu)) {
            FP_COMP_REG(i) = 0;
            return true;
        }
    }
    return false;
}

static uint8_t wp_size_bits(uint32_t len) {
    uint8_t m = 0;
    while ((1u << m) < len && m < 31) {
        m++;
    }
    return m;
}
static bool dwt_set(uint32_t addr, uint32_t len, uint32_t func) {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    for (uint8_t i = 0; i < GDB_MAX_WP; i++) {
        if (DWT_FUNC_REG(i) & 0xFu) {
            continue;
        }
        DWT_COMP_REG(i) = addr;
        DWT_MASK_REG(i) = wp_size_bits(len ? len : 4u);
        DWT_FUNC_REG(i) = func;   /* 5 read, 6 write, 7 read/write (data addr) */
        return true;
    }
    return false;
}
static bool dwt_clear(uint32_t addr) {
    for (uint8_t i = 0; i < GDB_MAX_WP; i++) {
        if ((DWT_FUNC_REG(i) & 0xFu) && DWT_COMP_REG(i) == addr) {
            DWT_FUNC_REG(i) = 0;
            return true;
        }
    }
    return false;
}

/* gdb Z/z: 0,1 -> FPB breakpoint; 2 write / 3 read / 4 access -> DWT. */
static void do_bp(const char *s, const char *end, bool set) {
    if (end - s < 2) { send_empty(); return; }
    char type = s[1];
    const char *p = s + 2;
    if (p < end && *p == ',') p++;
    uint32_t addr = 0, kindlen = 0;
    parse_hex(&p, end, &addr);
    if (p < end && *p == ',') { p++; parse_hex(&p, end, &kindlen); }
    bool ok;
    switch (type) {
        case '0': case '1': ok = set ? fpb_set(addr) : fpb_clear(addr); break;
        case '2': ok = set ? dwt_set(addr, kindlen, 6) : dwt_clear(addr); break;
        case '3': ok = set ? dwt_set(addr, kindlen, 5) : dwt_clear(addr); break;
        case '4': ok = set ? dwt_set(addr, kindlen, 7) : dwt_clear(addr); break;
        default: send_empty(); return;
    }
    if (ok) send_ok(); else send_err(0x01);
}

/* Enable monitor-mode debug. Works only with no SWD attached (SWD halting
 * debug overrides MON_EN). DebugMon runs at the lowest exception priority so
 * USB and the SoftDevice preempt it and keep running while stopped. */
static void gdb_debug_init(void) {
    m_halted = false;
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    fpb_enable();
    NVIC_SetPriority(DebugMonitor_IRQn, (1u << __NVIC_PRIO_BITS) - 1u);
    CoreDebug->DEMCR |= CoreDebug_DEMCR_MON_EN_Msk;
}
static void bp_clear_all(void) {
    for (uint8_t i = 0; i < GDB_MAX_HWBP; i++) FP_COMP_REG(i) = 0;
    for (uint8_t i = 0; i < GDB_MAX_WP; i++)   DWT_FUNC_REG(i) = 0;
}
static void gdb_debug_deinit(void) {
    bp_clear_all();
    CoreDebug->DEMCR &= ~(CoreDebug_DEMCR_MON_EN_Msk | CoreDebug_DEMCR_MON_STEP_Msk);
    m_halted = false;
}

/* C body of the DebugMon exception: assemble registers from the stacked frame
 * and the saved r4-r11, send a stop reply, then service gdb until it resumes. */
void gdb_mon_handle(uint32_t *frame, uint32_t exc_return, uint32_t *r4_11) {
    for (int i = 0; i < 4; i++)  m_regs[i]     = frame[i];   /* r0-r3  */
    for (int i = 0; i < 8; i++)  m_regs[4 + i] = r4_11[i];   /* r4-r11 */
    m_regs[12] = frame[4];   /* r12 */
    m_regs[14] = frame[5];   /* lr  */
    m_regs[15] = frame[6];   /* pc  */
    m_regs[16] = frame[7];   /* xPSR */
    uint32_t sp = (uint32_t)frame + 32u;                 /* basic frame = 8 words */
    if (frame[7] & (1u << 9)) sp += 4u;                  /* stack-align padding   */
    if ((exc_return & 0x10u) == 0u) sp += 72u;           /* FPU extended frame    */
    m_regs[13] = sp;

    CoreDebug->DEMCR &= ~CoreDebug_DEMCR_MON_STEP_Msk;
    m_halted = true;
    m_run = 0;
    send_str("S05");                 /* unsolicited stop reply to gdb */

    while (m_run == 0) {
        /* If the active link dropped (gdb quit, cable yank, BLE disconnect)
         * while stopped, resume and disarm breakpoints so the firmware does
         * not stay frozen in here. g_usb_port_opened is only meaningful on
         * USB, so also accept a live BLE NUS link. */
        if (!g_usb_port_opened && !is_nus_working()) {
            bp_clear_all();
            m_run = 1;
            break;
        }
        app_usbd_event_queue_process();   /* keep the CDC/RSP alive while stopped */
        bsp_wdt_feed();
    }

    for (int i = 0; i < 4; i++)  frame[i]  = m_regs[i];
    for (int i = 0; i < 8; i++)  r4_11[i]  = m_regs[4 + i];
    frame[4] = m_regs[12];
    frame[5] = m_regs[14];
    frame[6] = m_regs[15];   /* gdb may have moved pc */
    frame[7] = m_regs[16];

    m_halted = false;
}

/* Exception entry: pick the active stack, hand the stacked frame + a saved
 * copy of r4-r11 to the C body, restore on return (gdb edits take effect). */
__attribute__((naked)) void DebugMon_Handler(void) {
    __asm volatile(
        "tst   lr, #4            \n"
        "ite   eq                \n"
        "mrseq r0, msp           \n"
        "mrsne r0, psp           \n"
        "mov   r1, lr            \n"
        "push  {r4-r11, lr}      \n"
        "mov   r2, sp            \n"
        "bl    gdb_mon_handle    \n"
        "pop   {r4-r11, lr}      \n"
        "bx    lr                \n"
    );
}

#endif /* CONFIG_GDB_GATEWAY_EXEC */

/* ---- qRcmd ("monitor <cmd>") ---------------------------------------- */
/* Reply payload is hex-encoded ASCII; gdb prints it on the console. An empty
 * reply means "unknown command". */
static void mon_reply(const char *txt) {
    uint16_t j = 0;
    for (const char *p = txt; *p && j + 2u <= GDB_OUT_MAX; p++) {
        m_out[j++] = HEXD[(uint8_t)*p >> 4];
        m_out[j++] = HEXD[(uint8_t)*p & 0xF];
    }
    send_payload(m_out, j);
}

/* Decode the hex-encoded command after "qRcmd,", NUL-terminating `out`. */
static void mon_decode(const char *p, const char *end, char *out, uint16_t max) {
    uint16_t n = 0;
    while (p + 1 < end && n + 1u < max) {
        int hi = hexval((uint8_t)p[0]);
        int lo = hexval((uint8_t)p[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (char)((hi << 4) | lo);
        p += 2;
    }
    out[n] = 0;
}

static void do_monitor(const char *p, const char *end) {
    char cmd[64];
    mon_decode(p, end, cmd, sizeof(cmd));
    for (int i = (int)strlen(cmd) - 1;             /* trim trailing ws gdb adds */
         i >= 0 && (cmd[i] == ' ' || cmd[i] == '\n' || cmd[i] == '\r'); i--) {
        cmd[i] = 0;
    }

    if (cmd[0] == 0 || strcmp(cmd, "help") == 0) {
        mon_reply("ChameleonUltra GDB gateway (no SWD)\n"
                  "  monitor help        this list\n"
                  "  monitor info        gateway state\n"
                  "  monitor unlock-app  allow writes into the app region\n"
                  "  monitor lock        restore the default write floor\n"
                  "  monitor reset       reboot the device (drops this gdb link)\n");
        return;
    }
    if (strcmp(cmd, "unlock-app") == 0) {
        m_wr_min = APP_FLASH_BASE;
        mon_reply("app region writable: 0x027000-0x100000.\n"
                  "WARNING: erasing/writing a page the running app, SoftDevice\n"
                  "or this monitor executes from WILL hardfault - a full app\n"
                  "load from the running app cannot work (use UF2/DFU). For\n"
                  "targeted patches to idle pages only. 'monitor lock' restores.\n");
        return;
    }
    if (strcmp(cmd, "lock") == 0) {
        m_wr_min = SAFE_FLASH_MIN;
        mon_reply("write floor restored to 0x0C7000.\n");
        return;
    }
    if (strcmp(cmd, "info") == 0) {
        char b[224];
        int n = snprintf(b, sizeof(b), "flash write window: 0x%06lX-0x%06lX%s\n",
                         (unsigned long)m_wr_min, (unsigned long)SAFE_FLASH_MAX,
                         m_wr_min < SAFE_FLASH_MIN ? "  [app unlocked]" : "");
#if CONFIG_GDB_GATEWAY_EXEC
        snprintf(b + n, sizeof(b) - n, "exec: on  hw-bp: %u  wp: %u  state: %s\n",
                 (unsigned)m_ncode, (unsigned)GDB_MAX_WP, m_halted ? "halted" : "running");
#else
        snprintf(b + n, sizeof(b) - n, "exec: off (memory read + flash load only)\n");
#endif
        mon_reply(b);
        return;
    }
    if (strcmp(cmd, "reset") == 0) {
        mon_reply("resetting\n");
        fl_flush(true);
        fl_reset();
        delayed_reset(100);        /* canonical path; non-blocking, lets CDC drain */
        return;
    }
    send_empty();                  /* unknown monitor command */
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
        case 'g': {            /* read all registers (r0-r15, xPSR) */
            uint16_t j = 0;
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) {
                for (int i = 0; i < 17; i++) { word_le_hex(&m_out[j], m_regs[i]); j += 8; }
                send_payload(m_out, j);
                return;
            }
#endif
            for (int i = 0; i < 17 * 8; i++) m_out[j++] = '0';   /* running: unknown */
            send_payload(m_out, j);
            return;
        }
        case 'G':
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) {
                const char *p = s + 1;
                for (int i = 0; i < 17 && p + 8 <= end; i++) { m_regs[i] = hex_le_word(p); p += 8; }
            }
#endif
            send_ok();
            return;
        case 'p': {            /* read one register */
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) {
                const char *p = s + 1;
                uint32_t n = 0;
                parse_hex(&p, end, &n);
                word_le_hex(m_out, n < 17 ? m_regs[n] : 0);
                send_payload(m_out, 8);
                return;
            }
#endif
            memcpy(m_out, "00000000", 8);
            send_payload(m_out, 8);
            return;
        }
        case 'P':
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) {
                const char *p = s + 1;
                uint32_t n = 0;
                parse_hex(&p, end, &n);
                if (p < end && *p == '=') { p++; if (n < 17) m_regs[n] = hex_le_word(p); }
            }
#endif
            send_ok();
            return;
        case 'H':
            send_ok();
            return;
        case 'm':
            do_mem_read(s + 1, end);
            return;
        case 'M':
            do_mem_write(s + 1, end);
            return;
        case 'c': case 'C':
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) {        /* leave the DebugMon loop; stop reply on next halt */
                send_ack();
                m_run = 1;
                return;
            }
            /* Running: no async halt (forcing a stop from the RSP/USB path
             * reenters the USB stack and corrupts it), so just ack and the stop
             * reply comes when a breakpoint fires. */
            send_ack();
            return;
#else
            send_str("S05");       /* no execution control */
            return;
#endif
        case 's': case 'S':
            /* Hardware single-step is not offered: resuming for one instruction
             * lets a USB/SoftDevice interrupt escape the step and drop the link.
             * gdb single-steps in software (temp breakpoints + continue), so a
             * stray s/S is a harmless no-op reported as stopped. */
            send_str("S05");
            return;
        case 'D':
            /* Detach: resume the core and clear breakpoints so the target runs
             * free (and can be disarmed by button) instead of staying frozen in
             * the DebugMon loop. The mode stays armed so gdb can reconnect. */
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) { bp_clear_all(); m_run = 1; }
#endif
            fl_flush(true);
            fl_reset();
            send_ok();
            return;
        case 'k':
            /* Kill/quit: resume + clear breakpoints too, then no reply. */
#if CONFIG_GDB_GATEWAY_EXEC
            if (m_halted) { bp_clear_all(); m_run = 1; }
#endif
            fl_flush(true);
            fl_reset();
            return;
        case 'R':
            send_ok();
            return;
        case 'z': case 'Z':
#if CONFIG_GDB_GATEWAY_EXEC
            do_bp(s, end, c == 'Z');
#else
            send_empty();       /* no breakpoint/watchpoint support */
#endif
            return;
        case 'q':
            if (str_pref(s, len, "qSupported")) {
                int n = snprintf(m_out, GDB_OUT_MAX,
                                 "PacketSize=%lx;qXfer:memory-map:read+;qXfer:features:read+",
                                 (unsigned long)GDB_PACKET_SIZE);
                send_payload(m_out, (uint16_t)n);
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
            if (str_pref(s, len, "qRcmd,")) { do_monitor(s + 6, end); return; }
            send_empty();
            return;
        case 'v':
            if (str_pref(s, len, "vMustReplyEmpty")) { send_empty(); return; }
#if CONFIG_GDB_GATEWAY_EXEC
            /* Advertise continue only. gdb then single-steps in software (temp
             * breakpoints + continue), avoiding the fragile hardware step. */
            if (str_pref(s, len, "vCont?")) { send_str("vCont;c;C"); return; }
            if (str_pref(s, len, "vCont;")) {
                if (m_halted) { send_ack(); m_run = 1; return; }
                send_ack();        /* running: stop reply comes on a breakpoint */
                return;
            }
#endif
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
#if CONFIG_GDB_GATEWAY_EXEC
                /* No async interrupt: halting from this (USB/RSP) context
                 * reenters the USB stack. Stop the target with a breakpoint. */
#else
                send_str("S05");    /* Ctrl-C interrupt (nothing to stop) */
#endif
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
    m_wr_min = SAFE_FLASH_MIN;   /* always start locked; unlock per session */
    fl_reset();
#if CONFIG_GDB_GATEWAY_EXEC
    gdb_debug_init();
#endif
    m_active = true;
    NRF_LOG_INFO("GDB RSP gateway active on CDC");
}

void gdb_rsp_leave(void) {
    fl_flush(true);         /* commit any buffered bytes before leaving */
    fl_reset();
#if CONFIG_GDB_GATEWAY_EXEC
    gdb_debug_deinit();
#endif
    m_active = false;
    NRF_LOG_INFO("GDB RSP gateway stopped");
}

bool gdb_rsp_active(void) {
    return m_active;
}
