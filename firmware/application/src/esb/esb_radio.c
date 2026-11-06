/*
 * esb_radio.c - passive Nordic proprietary-PHY (Enhanced ShockBurst framing)
 * receive in chained SoftDevice timeslots, matching a known 5-byte address.
 *
 * Architecture is identical to zb_radio.c (same SoftDevice radio-timeslot
 * session, same chained-slot/timer/NVIC pattern) -- only the packet framing
 * differs: Nrf_1Mbit/Nrf_2Mbit PHY instead of IEEE 802.15.4, address-matched
 * RX instead of promiscuous. See zb_radio.c for the timeslot mechanics; the
 * comments here only cover what's different.
 *
 * PCNF0/PCNF1/CRCCNF and the address byte-order conversion are NOT derived
 * from this repo or a local datasheet (neither exists here) -- they are
 * carried over from Nordic's own published Enhanced ShockBurst source,
 * cross-checked against two independent lineages: the classic nRF51/nRF52
 * micro_esb.c / nrf_esb.c SDK library, and the newer Zephyr-integrated
 * esb.c (both Copyright Nordic Semiconductor ASA). Specifically:
 *   - PCNF0 (S0LEN=0, LFLEN=6, S1LEN=3) and PCNF1 (WHITEEN disabled,
 *     ENDIAN=Big, BALEN=addr_len-1, STATLEN=0, MAXLEN=32) match
 *     update_rf_payload_format_esb_dpl() in micro_esb.c -- "Dynamic Payload
 *     Length" framing, needed here because real-world payloads vary in size
 *     (e.g. a Logitech Unifying frame is 5, 10, or 22 bytes).
 *   - CRCCNF/CRCINIT/CRCPOLY (16-bit, init 0xFFFF, poly 0x11021) match the
 *     CRCCNF_LEN_Two branch in the same source. CRCCNF's SKIPADDR bits are
 *     deliberately left unset here, same as nrf_esb.c's own CRCCNF write --
 *     it never ORs in a SKIPADDR value either, so this matches rather than
 *     guesses one.
 *   - The address-to-register conversion (addr_conv: swap the bit order
 *     within each byte, then reverse byte order) matches Zephyr's esb.c
 *     addr_conv()/bytewise_bit_swap(), used to go from the MSB-first byte
 *     order these addresses are normally written in to what BASE0/PREFIX0
 *     expect.
 * What is NOT verified against any Nordic source pulled so far: the actual
 * on-air CRC width a given peripheral uses (16-bit here is the common
 * default; if rx_crc never clears, 8-bit -- RADIO_CRCCNF_LEN_One, CRCINIT
 * 0xFF, CRCPOLY 0x107 -- is the first thing to try) and the bitrate
 * (Nrf_2Mbit is the default passed in from mode_esb.c; Nrf_1Mbit is the
 * fallback). Both are left as runtime config precisely because they're
 * unverified assumptions, not hard facts.
 */

#include "esb_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US        50000u
#define SLOT_MIN_US    5000u
#define SLOT_GROW_US   5000u
#define TIMEOUT_US     200000u
#define GROW_EVERY     16u
#define STOP_GUARD_US  2000u
#define RING_SZ        8u

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;
static volatile bool    m_open;
static volatile uint8_t m_channel = 2;          /* wanted, 0..100 MHz offset from 2400 */
static uint8_t          m_slot_ch = 2;          /* in use this slot */
static uint8_t          m_addr[5];              /* addr[0]=prefix byte, addr[1..4]=base */
static bool              m_2mbit = true;
static uint8_t           m_pkt[1 + ESB_MAX_PAYLOAD];   /* [LENGTH byte][payload] */
static esb_frame_t       m_ring[RING_SZ];
static volatile uint8_t  m_head, m_tail;
static volatile bool     m_rereq;
static volatile uint32_t m_slot_us = SLOT_US;
static uint32_t          m_cur_us  = SLOT_US;
static volatile esb_stats_t m_st;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

/* Bit-reverse within each byte of a 32-bit word, then reverse byte order --
 * converts a 4-byte chunk of an address from the MSB-first order it's
 * normally written in to what BASE0/PREFIX0 expect on this radio. Matches
 * Zephyr esb.c's addr_conv()/bytewise_bit_swap() exactly. */
static uint32_t addr_conv(uint32_t inp) {
    inp = (inp & 0xF0F0F0F0UL) >> 4 | (inp & 0x0F0F0F0FUL) << 4;
    inp = (inp & 0xCCCCCCCCUL) >> 2 | (inp & 0x33333333UL) << 2;
    inp = (inp & 0xAAAAAAAAUL) >> 1 | (inp & 0x55555555UL) << 1;
    return __REV(inp);
}

static void radio_rx_begin(void) {
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE  = (m_2mbit ? RADIO_MODE_MODE_Nrf_2Mbit : RADIO_MODE_MODE_Nrf_1Mbit)
                        << RADIO_MODE_MODE_Pos;
    /* Dynamic Payload Length framing -- see file header for source. */
    NRF_RADIO->PCNF0 = (0UL << RADIO_PCNF0_S0LEN_Pos) |
                       (6UL << RADIO_PCNF0_LFLEN_Pos) |
                       (3UL << RADIO_PCNF0_S1LEN_Pos);
    NRF_RADIO->PCNF1 = (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos) |
                       (RADIO_PCNF1_ENDIAN_Big        << RADIO_PCNF1_ENDIAN_Pos) |
                       (4UL                           << RADIO_PCNF1_BALEN_Pos) |   /* 5-byte addr: BALEN = len-1 */
                       (0UL                           << RADIO_PCNF1_STATLEN_Pos) |
                       (ESB_MAX_PAYLOAD               << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF  = RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos;   /* SKIPADDR left unset, matches source */
    NRF_RADIO->CRCPOLY = 0x11021UL;
    NRF_RADIO->CRCINIT = 0xFFFFUL;

    NRF_RADIO->BASE0   = addr_conv(((uint32_t)m_addr[1] << 24) | ((uint32_t)m_addr[2] << 16) |
                                    ((uint32_t)m_addr[3] << 8)  |  (uint32_t)m_addr[4]);
    NRF_RADIO->PREFIX0 = addr_conv((uint32_t)m_addr[0]);   /* pipe 0's prefix byte, low byte of the word */
    NRF_RADIO->RXADDRESSES = RADIO_RXADDRESSES_ADDR0_Enabled << RADIO_RXADDRESSES_ADDR0_Pos;

    m_slot_ch            = m_channel;
    NRF_RADIO->FREQUENCY = m_slot_ch;   /* direct MHz offset from 2400, 0..100 */
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_RXREADY_START_Msk;
    NRF_RADIO->EVENTS_END     = 0;
    NRF_RADIO->EVENTS_ADDRESS = 0;
    NRF_RADIO->EVENTS_READY   = 0;
    NRF_RADIO->INTENSET      = RADIO_INTENSET_END_Msk | RADIO_INTENSET_ADDRESS_Msk;

    NRF_TIMER0->CC[0]             = m_cur_us - STOP_GUARD_US;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE0_Msk;

    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);

    NRF_RADIO->TASKS_RXEN = 1;
    for (uint32_t i = 0; i < 4000 && !NRF_RADIO->EVENTS_READY; i++) {
        __NOP();
    }
    if (NRF_RADIO->EVENTS_READY) m_st.ready_ok++; else m_st.ready_timeout++;
}

static void radio_off(void) {
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE0_Msk;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_RADIO->SHORTS    = 0;
    NRF_RADIO->INTENCLR  = RADIO_INTENCLR_END_Msk | RADIO_INTENCLR_ADDRESS_Msk;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t i = 0; i < 2000 && !NRF_RADIO->EVENTS_DISABLED; i++) {
        __NOP();
    }
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END      = 0;
}

/* RAM: [LENGTH byte, low 6 bits][payload]; confirmed against nrf_esb's own
 * DPL rx handler, which reads byte 0 of its RX buffer as the length
 * ("if (m_rx_payload_buffer[0] > MAX_PAYLOAD_LENGTH) return false") --
 * same PHR-first convention zb_radio.c already relies on for 802.15.4,
 * just a 6-bit field here instead of 7. */
static void radio_frame(void) {
    NRF_RADIO->EVENTS_END = 0;
    bool    ok  = NRF_RADIO->CRCSTATUS == RADIO_CRCSTATUS_CRCSTATUS_CRCOk;
    uint8_t len = m_pkt[0] & 0x3FUL;

    if (!ok) {
        m_st.rx_crc++;
    } else if (len > 0 && len <= ESB_MAX_PAYLOAD) {
        uint8_t next = (uint8_t)((m_head + 1u) % RING_SZ);
        if (next == m_tail) {
            m_st.dropped++;
        } else {
            esb_frame_t *f = &m_ring[m_head];
            f->channel = m_slot_ch;
            f->len = len;
            memcpy(f->data, &m_pkt[1], len);
            m_head = next;
            m_st.rx_ok++;
        }
    }
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->TASKS_START = 1;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START:
            m_st.slots++;
            m_cur_us = m_req.params.earliest.length_us;
            if (m_st.slots % GROW_EVERY == 0 && m_slot_us < SLOT_US) m_slot_us += SLOT_GROW_US;
            radio_rx_begin();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_RADIO:
            m_st.sig_radio++;
            if (NRF_RADIO->EVENTS_ADDRESS) {
                NRF_RADIO->EVENTS_ADDRESS = 0;
                m_st.address_evt++;
            }
            if (NRF_RADIO->EVENTS_END) radio_frame();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_TIMER0:
            m_st.sig_timer0++;
            radio_off();
            if (m_run) {
                fill_request();
                m_ret.params.request.p_next = &m_req;
                m_ret.callback_action       = NRF_RADIO_SIGNAL_CALLBACK_ACTION_REQUEST_AND_END;
            } else {
                m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_END;
            }
            break;
        default:
            break;
    }
    return &m_ret;
}

static void soc_evt(uint32_t evt, void *ctx) {
    (void)ctx;
    if (!m_open) return;
    switch (evt) {
        case NRF_EVT_RADIO_BLOCKED:
        case NRF_EVT_RADIO_CANCELED:
            if (evt == NRF_EVT_RADIO_BLOCKED) m_st.blocked++; else m_st.canceled++;
            if (m_slot_us > SLOT_MIN_US) m_slot_us = (m_slot_us / 2 > SLOT_MIN_US) ? m_slot_us / 2 : SLOT_MIN_US;
            m_rereq = true;
            break;
        case NRF_EVT_RADIO_SESSION_IDLE:
            m_st.idle++;
            if (!m_run) (void)sd_radio_session_close();
            break;
        case NRF_EVT_RADIO_SESSION_CLOSED:
            m_open = false;
            break;
        default:
            break;
    }
}
NRF_SDH_SOC_OBSERVER(m_esb_obs, 0, soc_evt, NULL);

void esb_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool esb_radio_start(const uint8_t addr[5], uint8_t channel, bool bitrate_2mbit) {
    if (m_open || addr == NULL || channel > 100) return false;
    memset((void *)&m_st, 0, sizeof(m_st));
    m_slot_us = SLOT_US;
    m_head = m_tail = 0;
    memcpy(m_addr, addr, 5);
    m_channel = channel;
    m_2mbit   = bitrate_2mbit;
    m_run = true;
    if (sd_radio_session_open(radio_cb) != NRF_SUCCESS) {
        m_run = false;
        return false;
    }
    m_open = true;
    fill_request();
    if (sd_radio_request(&m_req) != NRF_SUCCESS) {
        m_run = false;
        (void)sd_radio_session_close();
        return false;
    }
    return true;
}

void esb_radio_set_channel(uint8_t channel) {
    if (channel <= 100) m_channel = channel;
}

void esb_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();
}

bool esb_radio_running(void) {
    return m_run;
}

bool esb_radio_pop(esb_frame_t *out) {
    if (m_tail == m_head) return false;
    *out = m_ring[m_tail];
    m_tail = (uint8_t)((m_tail + 1u) % RING_SZ);
    return true;
}

void esb_radio_get_stats(esb_stats_t *out) {
    *out = *(const esb_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}
