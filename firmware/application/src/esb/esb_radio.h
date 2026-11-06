#ifndef ESB_RADIO_H__
#define ESB_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#define ESB_MAX_PAYLOAD  32u    /* hardware ceiling for a Nordic ESB/proprietary-mode payload */

typedef struct {
    uint8_t channel;                /* 0..100, MHz offset from 2400 (direct FREQUENCY value) */
    uint8_t len;                    /* payload length, from the packet's 6-bit LFLEN field */
    uint8_t data[ESB_MAX_PAYLOAD];
} esb_frame_t;

typedef struct {
    uint32_t slots, blocked, canceled;
    uint32_t rx_ok;                 /* frames with a good CRC */
    uint32_t rx_crc;                /* frames with a bad CRC */
    uint32_t dropped;               /* good frames lost, ring full */
    uint32_t sig_radio, sig_timer0, idle;
    uint32_t last_rc;
    uint32_t ready_ok, ready_timeout;
    uint32_t address_evt;           /* EVENTS_ADDRESS count -- our address matched on air */
    uint32_t slot_us;
} esb_stats_t;

/* Passive receive of Nordic proprietary-PHY (Enhanced ShockBurst-framed)
 * packets matching a known 5-byte address, one fixed channel or hopping
 * 0..100, chained SoftDevice timeslots -- same architecture as zb_radio.c,
 * different packet framing (Nrf_1Mbit/Nrf_2Mbit PHY, not 802.15.4). This is
 * RX only; nothing is transmitted.
 *
 * addr[0] is the pipe prefix byte, addr[1..4] the base address, in the
 * order these addresses are normally written/exchanged (e.g. a Logitech
 * Unifying receiver's own address convention -- see mode_esb.c). bitrate_2mbit
 * selects Nrf_2Mbit (true) or Nrf_1Mbit (false); which one a given peripheral
 * actually uses isn't something this code can detect, only the caller/config.
 *
 * Register configuration (PCNF0/PCNF1/CRCCNF/address byte-order conversion)
 * is carried over from Nordic's own published ESB source (nrf_esb.c /
 * Zephyr's esb.c), not reverse-engineered here -- see esb_radio.c. The one
 * thing NOT verified against a real Nordic doc or source: Logitech Unifying's
 * actual on-air CRC width (this defaults to 16-bit, the common ESB default;
 * if captures never show CRCOK, 8-bit is the first thing to try).
 */
bool esb_radio_start(const uint8_t addr[5], uint8_t channel, bool bitrate_2mbit);
void esb_radio_set_channel(uint8_t channel);   /* takes effect at the next timeslot */
void esb_radio_stop(void);
bool esb_radio_running(void);
bool esb_radio_pop(esb_frame_t *out);
void esb_radio_poll(void);              /* call periodically from main context */
void esb_radio_get_stats(esb_stats_t *out);

#endif
