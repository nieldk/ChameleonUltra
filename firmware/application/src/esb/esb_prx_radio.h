#ifndef ESB_PRX_RADIO_H__
#define ESB_PRX_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#include "esb_radio.h"      /* esb_frame_t, ESB_MAX_PAYLOAD */

typedef struct {
    uint32_t slots, blocked, canceled, idle;
    uint32_t rx_ok;          /* frames received with a good CRC */
    uint32_t rx_crc;         /* bad-CRC receptions */
    uint32_t acks;           /* ACK frames transmitted */
    uint32_t dropped;        /* good frames lost, ring full */
    uint32_t last_rc;
    uint32_t slot_us;
} esb_prx_stats_t;

/* Emulate an ESB PRX (receiver) on a known 5-byte address: receive frames and,
 * when ack_enable is set, transmit an ESB ACK one ramp after each good-CRC
 * frame -- the DISABLED-driven RX->TX turnaround from Nordic's ESB PRX
 * (nrf_esb_illegalmod on_radio_disabled_rx). This lets a second CU answer
 * esb-enum and ACK esb-inject like a real dongle, on top of the RX+decrypt the
 * esb-prx mode already does.
 *
 * Framing/address config matches esb_radio.c (base-first addr, S1 excluded from
 * RAM so the frame layout and the len-0 ACK are the same). UNBUILT/untested
 * here; the ACK turnaround timing is the bring-up variable -- if enum sees no
 * acks, ack_enable can be turned off to fall back to pure RX.
 */
bool esb_prx_radio_start(const uint8_t addr[5], uint8_t channel,
                         bool bitrate_2mbit, bool ack_enable);
void esb_prx_radio_set_channel(uint8_t channel);
void esb_prx_radio_stop(void);
bool esb_prx_radio_running(void);
bool esb_prx_radio_pop(esb_frame_t *out);
void esb_prx_radio_poll(void);
void esb_prx_radio_get_stats(esb_prx_stats_t *out);

#endif
