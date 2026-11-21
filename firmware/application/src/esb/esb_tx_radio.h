#ifndef ESB_TX_RADIO_H__
#define ESB_TX_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#include "esb_radio.h"      /* ESB_MAX_PAYLOAD */

#define ESB_TX_MAX_FRAMES   64u     /* keystrokes are press+release pairs: 64 = ~32 chars */
#define ESB_TX_MAX_CHANNELS 32u     /* Unifying hop set is 25 */

typedef struct {
    uint32_t slots, blocked, canceled, idle;
    uint32_t tx_attempts;           /* TXEN issued */
    uint32_t tx_done;               /* EVENTS_END seen after a TX (frame left the antenna) */
    uint32_t tx_timeout;            /* END never fired within the bounded spin */
    uint32_t sweeps;                /* full channel sweeps completed */
    uint32_t frames_sent;           /* logical frames transmitted across the whole sweep */
    uint32_t last_rc;
    uint32_t slot_us;
} esb_tx_stats_t;

/* Transmit (inject) a batch of already-built ESB frames on a known 5-byte
 * address, as a PTX, under chained SoftDevice timeslots -- the transmit
 * counterpart of esb_radio.c. Same register configuration and address
 * byte-order conversion as that file (carried from Nordic's ESB source, see
 * esb_tx_radio.c); the only on-air difference is PCNF0 S1INCL=Include, so the
 * 9-bit PCF's PID/no_ack bits are driven from RAM (PID increments per logical
 * frame so the receiver does not discard successive frames as duplicates).
 *
 * Each frame is transmitted once per channel across `channels` (the receiver
 * hops, so the sweep lands the frame wherever it is listening), optionally
 * repeating the whole job `repeat` times. Frames carry no_ack=0, i.e. the
 * receiver still ACKs and processes them; this v1 does not turn the radio
 * around to read that ACK (blind sweep), so delivery is by redundancy, not
 * confirmation. ACK-confirmed stop is a documented follow-up.
 *
 * addr is base-first [base0..3, prefix], same convention as esb_radio_start
 * and a promiscuous capture. frames is `count` records of `lens[i]` bytes each (the raw
 * ESB payload, no length/CRC -- the radio frames and CRCs them). channels is
 * `n_ch` MHz offsets from 2400. per_frame_gap_ms spaces successive logical
 * frames (8 ms for Unifying; shorter drops USB HID reports on some hosts).
 * Returns false on a bad argument or if a session is already open.
 */
bool esb_tx_radio_start(const uint8_t addr[5],
                        const uint8_t *frames, const uint16_t *lens, uint8_t count,
                        const uint8_t *channels, uint8_t n_ch,
                        bool bitrate_2mbit, uint8_t per_frame_gap_ms, uint8_t repeat);
bool esb_tx_radio_running(void);
bool esb_tx_radio_done(void);           /* job finished (all frames * repeats sent) */
void esb_tx_radio_poll(void);           /* call periodically from main context */
void esb_tx_radio_stop(void);
void esb_tx_radio_get_stats(esb_tx_stats_t *out);

#endif
