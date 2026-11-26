#ifndef ESB_PROMISC_RADIO_H__
#define ESB_PROMISC_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#define ESB_PROMISC_CAP_LEN  32u   /* fixed raw-capture length, see esb_promisc_radio.c. Must cover a
                                    * full 22-byte Unifying frame: addr(5)+PCF(2)+22+CRC(2) = 31 bytes,
                                    * so 26 truncated encrypted-keyboard and pairing frames below their CRC. */

typedef struct {
    uint8_t channel;
    uint8_t prefix_guess;              /* which of the 8 fixed pipes matched (0..7) */
    uint8_t base_guess;                 /* that pipe's fixed prefix byte, for the log */
    uint8_t raw[ESB_PROMISC_CAP_LEN];  /* captured from the real address onward: addr + PCF + payload + CRC */
} esb_promisc_frame_t;

typedef struct {
    uint32_t slots, blocked, canceled;
    uint32_t hits;                    /* EVENTS_END fired (synced on a preamble match) */
    uint32_t dropped;                 /* hits lost, ring full */
    uint32_t sig_radio, sig_timer0, idle;
    uint32_t last_rc;
    uint32_t ready_ok, ready_timeout;
    uint32_t guesses_tried;           /* retained for ABI/log compat; unused in preamble-sync */
    uint32_t slot_us;
} esb_promisc_stats_t;

/* ESB/proprietary-PHY sniffer for an UNKNOWN address, ported from LOGITacker's
 * (mame82/RoganDawes) nrf_esb_illegalmod.c -- the proven-working design on
 * this exact RADIO family, not an original scheme. BALEN=1 (one base + one
 * prefix byte matched, still below the documented 2..4 range but functional
 * on real silicon) is matched on all 8 logical pipes at once, each pipe a
 * different fixed base/prefix, so the illegal 2-byte match space is spread
 * across 8 guesses simultaneously instead of relying on one. CRC is off (no
 * way to validate an unknown frame on-device); PCF + payload + CRC land in the
 * fixed-length capture, starting at the matched address. The host validates
 * the 2-byte ESB CRC-16 over the capture to separate real frames from the
 * inevitable noise matches a 2-byte illegal address produces (see
 * cli_esb.esb_crc_candidates). An earlier version of this file tried BALEN=0
 * on a single pipe, matching only the preamble byte; that isn't a mode the
 * nRF52 RADIO documents or supports, and it never caught a real device.
 *
 * prefix_lo/prefix_hi are kept in the signature for config-blob compatibility
 * but are unused -- the fixed 8-pipe scheme above matches all of them at
 * once, nothing is selected or brute-forced per call. channel 0..100 is the
 * direct 2400+N MHz offset.
 */
bool esb_promisc_radio_start(uint8_t channel, uint8_t prefix_lo, uint8_t prefix_hi);
void esb_promisc_radio_stop(void);
void esb_promisc_radio_set_channel(uint8_t channel);   /* takes effect at the next timeslot */
bool esb_promisc_radio_running(void);
bool esb_promisc_radio_pop(esb_promisc_frame_t *out);
void esb_promisc_radio_poll(void);
void esb_promisc_radio_get_stats(esb_promisc_stats_t *out);

#endif
