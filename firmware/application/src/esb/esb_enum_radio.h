#ifndef ESB_ENUM_RADIO_H__
#define ESB_ENUM_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#include "esb_radio.h"      /* ESB_MAX_PAYLOAD */

#define ESB_ENUM_MAX_CHANNELS 32u

typedef struct {
    uint32_t slots, blocked, canceled, idle;
    uint32_t pings;          /* TXEN issued */
    uint32_t tx_timeout;     /* TX END never fired */
    uint32_t acks;           /* ACKs received (CRCOK on the turnaround RX) */
    uint16_t prefixes_done;  /* 0..256 progress */
    uint8_t  found_count;    /* prefixes that ACKed */
    uint32_t last_rc;
    uint32_t slot_us;
} esb_enum_stats_t;

/* Active enumeration of a Unifying dongle: for a fixed 4-byte base address,
 * ping each prefix (device/pipe byte) and use the ESB ACK as the detector --
 * a prefix the dongle listens on ACKs, revealing a paired device address
 * without the device itself transmitting. This is mame82's active_enum, done
 * as a PTX-with-ACK under SoftDevice timeslots.
 *
 * The ACK turnaround mirrors Nordic's ESB PTX (nrf_esb_illegalmod): after
 * TXEN the radio sends, END-disables, and DISABLED_RXEN-ramps to RX; a CRCOK
 * RX within the retransmit window is the ACK. Each prefix is tried across the
 * channel set until one ACKs (the dongle hops).
 *
 * base[0..3] is the 4-byte base in the usual write order; channels are MHz
 * offsets; prefix_lo..prefix_hi is the inclusive prefix range (0x00..0xFF for
 * a full sweep; prefix 0x00 is the dongle's own address). UNBUILT here; the
 * ACK timing needs bench bring-up. Returns false on a bad argument or if a
 * session is already open.
 */
bool esb_enum_radio_start(const uint8_t base[4],
                          const uint8_t *channels, uint8_t n_ch,
                          bool bitrate_2mbit, uint8_t prefix_lo, uint8_t prefix_hi);
bool esb_enum_radio_running(void);
bool esb_enum_radio_done(void);          /* whole prefix range swept */
void esb_enum_radio_poll(void);
void esb_enum_radio_stop(void);
void esb_enum_radio_get_stats(esb_enum_stats_t *out);
void esb_enum_radio_get_found(uint8_t bitmap[32]);   /* bit p set = prefix p ACKed */

#endif
