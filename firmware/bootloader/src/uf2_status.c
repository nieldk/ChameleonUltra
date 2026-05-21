/*
 * uf2_status.c — UF2 transfer status tracking and status file content.
 *
 * No snprintf / printf dependency: uses inline helpers to format ints
 * to hex/decimal strings. Keeps the bootloader's flash budget honest.
 */

#include "uf2_status.h"
#include <string.h>

/* Static INFO_UF2.TXT — fully constant. Edit BL version string when
 * bumping bootloader_version in build.sh. */
static const char m_info_txt[] =
    "UF2 Bootloader for ChameleonUltra\r\n"
    "---------------------------------\r\n"
    "Model     : ChameleonUltra (nRF52840)\r\n"
    "Family ID : 0x1B57745F\r\n"
    "App range : 0x00027000 - 0x000F3000 (816 KB)\r\n"
    "Block sz  : 512 (UF2 standard, 256-byte payload)\r\n"
    "\r\n"
    "Drag a .uf2 file onto this drive to update the application.\r\n"
    "\r\n"
    "After each transfer attempt, read RESULT.TXT or FAIL.TXT to\r\n"
    "see whether the transfer succeeded and what was written.\r\n"
    "\r\n"
    "If a transfer fails repeatedly, try:\r\n"
    "  sudo dd if=app.uf2 of=/dev/sdX bs=512 \\\r\n"
    "      conv=notrunc oflag=direct,sync status=progress\r\n"
    "\r\n"
    "The 'sync' flag forces per-block ack, more reliable than plain\r\n"
    "drag-and-drop on some hosts.\r\n"
    "\r\n"
    "Source: github.com/nieldk/ChameleonUltra (UF2 branch)\r\n";

/* Dynamic buffers — content rebuilt as session state changes. */
static char m_result_txt[UF2_STATUS_RESULT_TXT_MAX];
static char m_fail_txt[UF2_STATUS_FAIL_TXT_MAX];

static uint32_t m_result_len;
static uint32_t m_fail_len;

/* Per-transfer session state. Cleared on init and on the first block
 * of a new transfer. */
static struct {
    uint32_t blocks_accepted;
    uint32_t blocks_rejected;
    uint32_t num_blocks_expected;
    uint32_t first_addr_written;
    uint32_t last_addr_written;
    uint32_t first_fail_block;
    uint32_t first_fail_addr;
    uf2_reject_reason_t first_fail_reason;
    bool transfer_in_progress;
    bool has_result;
    bool has_failure;
} m_session;


/* ---- inline string builders (no libc dependency) ---- */

static char *put_str(char *dst, const char *src)
{
    while (*src) {
        *dst++ = *src++;
    }
    return dst;
}

static char *put_hex32(char *dst, uint32_t val)
{
    static const char hex[] = "0123456789ABCDEF";
    *dst++ = '0';
    *dst++ = 'x';
    for (int i = 28; i >= 0; i -= 4) {
        *dst++ = hex[(val >> i) & 0xF];
    }
    return dst;
}

static char *put_dec32(char *dst, uint32_t val)
{
    if (val == 0) {
        *dst++ = '0';
        return dst;
    }
    char tmp[10];
    int len = 0;
    while (val > 0 && len < (int)sizeof(tmp)) {
        tmp[len++] = (char)('0' + (val % 10));
        val /= 10;
    }
    while (len > 0) {
        *dst++ = tmp[--len];
    }
    return dst;
}


/* ---- reason text + hint lookup ---- */

static const char *reason_label(uf2_reject_reason_t r)
{
    switch (r) {
        case UF2_REJECT_MAGIC:  return "MAGIC";
        case UF2_REJECT_FAMILY: return "FAMILY";
        case UF2_REJECT_BOUNDS: return "BOUNDS";
        case UF2_REJECT_WRITE:  return "WRITE";
        case UF2_REJECT_SEQ:    return "SEQ";
        default:                return "UNKNOWN";
    }
}

static const char *reason_hint(uf2_reject_reason_t r)
{
    switch (r) {
    case UF2_REJECT_MAGIC:
        return "  The UF2 file appears truncated or corrupted.\r\n"
               "  Re-generate it from a known-good source.";

    case UF2_REJECT_FAMILY:
        return "  uf2conv.py was not invoked with the nRF52840 family ID.\r\n"
               "  Use '-f 0x1B57745F' (Microsoft uf2conv) or set\r\n"
               "  --family=NRF52840.";

    case UF2_REJECT_BOUNDS:
        return "  target_addr is outside the writable application region\r\n"
               "  [0x00027000, 0x000F3000). Common causes:\r\n"
               "    - Converting .hex with a uf2conv.py that skips Intel\r\n"
               "      HEX type 02 (Extended Segment Address) records. Add\r\n"
               "      an 'elif rtype == 0x02:' clause in parse_hex().\r\n"
               "    - Using --base with wrong address for .bin input.\r\n"
               "    - Hex file linked at the wrong address.";

    case UF2_REJECT_WRITE:
        return "  Flash write failed. Possible causes:\r\n"
               "    - Block protection register (BPROT) is engaged.\r\n"
               "    - Flash worn out.\r\n"
               "  Recovery requires SWD access.";

    case UF2_REJECT_SEQ:
        return "  Block sequence is inconsistent. Either block_no is\r\n"
               "  beyond num_blocks, or num_blocks changed mid-transfer.\r\n"
               "  The UF2 file is malformed; re-generate it.";

    default:
        return "  Unknown rejection reason.";
    }
}


/* ---- API ---- */

void uf2_status_init(void)
{
    memset(&m_session, 0, sizeof(m_session));
    m_session.first_fail_reason = UF2_REJECT_NONE;
    m_result_len = 0;
    m_fail_len = 0;
}

/* Internal: detect start of a new transfer and clear prior result/fail. */
static void session_begin_if_needed(uint32_t num_blocks)
{
    if (!m_session.transfer_in_progress) {
        m_session.blocks_accepted     = 0;
        m_session.blocks_rejected     = 0;
        m_session.num_blocks_expected = num_blocks;
        m_session.first_addr_written  = 0;
        m_session.last_addr_written   = 0;
        m_session.first_fail_block    = 0;
        m_session.first_fail_addr     = 0;
        m_session.first_fail_reason   = UF2_REJECT_NONE;
        m_session.has_result          = false;
        m_session.has_failure         = false;
        m_session.transfer_in_progress = true;
        m_result_len = 0;
        m_fail_len = 0;
    }
}

void uf2_status_record_accepted(uint32_t block_no,
                                uint32_t num_blocks,
                                uint32_t target_addr)
{
    session_begin_if_needed(num_blocks);

    if (m_session.blocks_accepted == 0) {
        m_session.first_addr_written = target_addr;
    }
    m_session.blocks_accepted++;
    m_session.last_addr_written = target_addr + 256;
}

void uf2_status_record_rejected(uint32_t block_no,
                                uint32_t num_blocks,
                                uint32_t target_addr,
                                uf2_reject_reason_t reason)
{
    session_begin_if_needed(num_blocks);

    if (m_session.blocks_rejected == 0) {
        m_session.first_fail_block  = block_no;
        m_session.first_fail_addr   = target_addr;
        m_session.first_fail_reason = reason;
    }
    m_session.blocks_rejected++;
    m_session.has_failure = true;

    /* Rebuild FAIL.TXT every time so it always reflects current state */
    char *p = m_fail_txt;
    p = put_str(p, "ChameleonUltra UF2 -- Last transfer FAILED\r\n");
    p = put_str(p, "==========================================\r\n");
    p = put_str(p, "Reason  : ");
    p = put_str(p, reason_label(reason));
    p = put_str(p, "\r\n");
    p = put_str(p, "Block   : ");
    p = put_dec32(p, m_session.first_fail_block);
    p = put_str(p, " of ");
    p = put_dec32(p, m_session.num_blocks_expected);
    p = put_str(p, "\r\n");
    p = put_str(p, "Address : ");
    p = put_hex32(p, m_session.first_fail_addr);
    p = put_str(p, "\r\n");
    p = put_str(p, "Accepted: ");
    p = put_dec32(p, m_session.blocks_accepted);
    p = put_str(p, " blocks\r\n");
    p = put_str(p, "Rejected: ");
    p = put_dec32(p, m_session.blocks_rejected);
    p = put_str(p, " blocks\r\n");
    p = put_str(p, "\r\nHint:\r\n");
    p = put_str(p, reason_hint(reason));
    p = put_str(p, "\r\n\r\n");
    p = put_str(p, "Drag a corrected UF2 onto this drive to retry.\r\n");

    m_fail_len = (uint32_t)(p - m_fail_txt);
    if (m_fail_len > UF2_STATUS_FAIL_TXT_MAX) {
        m_fail_len = UF2_STATUS_FAIL_TXT_MAX;
    }
}

void uf2_status_record_complete(void)
{
    /* End of transfer. Only mark success if no blocks were rejected. */
    m_session.transfer_in_progress = false;

    if (m_session.blocks_rejected == 0 && m_session.blocks_accepted > 0) {
        m_session.has_result = true;

        char *p = m_result_txt;
        p = put_str(p, "ChameleonUltra UF2 -- Transfer SUCCESS\r\n");
        p = put_str(p, "======================================\r\n");
        p = put_str(p, "Blocks  : ");
        p = put_dec32(p, m_session.blocks_accepted);
        p = put_str(p, "\r\n");
        p = put_str(p, "Bytes   : ");
        p = put_dec32(p, m_session.blocks_accepted * 256);
        p = put_str(p, "\r\n");
        p = put_str(p, "Region  : ");
        p = put_hex32(p, m_session.first_addr_written);
        p = put_str(p, " - ");
        p = put_hex32(p, m_session.last_addr_written);
        p = put_str(p, "\r\n");
        p = put_str(p, "\r\n");
        p = put_str(p, "Device will reset and boot the new application.\r\n");

        m_result_len = (uint32_t)(p - m_result_txt);
        if (m_result_len > UF2_STATUS_RESULT_TXT_MAX) {
            m_result_len = UF2_STATUS_RESULT_TXT_MAX;
        }
    }
}

bool uf2_status_has_result(void)  { return m_session.has_result;  }
bool uf2_status_has_failure(void) { return m_session.has_failure; }

const char *uf2_status_get_info_txt(uint32_t *out_size)
{
    if (out_size) *out_size = sizeof(m_info_txt) - 1; /* exclude NUL */
    return m_info_txt;
}

const char *uf2_status_get_result_txt(uint32_t *out_size)
{
    if (out_size) *out_size = m_result_len;
    return m_result_txt;
}

const char *uf2_status_get_fail_txt(uint32_t *out_size)
{
    if (out_size) *out_size = m_fail_len;
    return m_fail_txt;
}
