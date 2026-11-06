#ifndef ESB_PROMISC_RADIO_H__
#define ESB_PROMISC_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#define ESB_PROMISC_CAP_LEN  26u   /* fixed raw-capture length, see esb_promisc_radio.c */

typedef struct {
    uint8_t channel;
    uint8_t prefix_guess;             /* PREFIX0 value that was active on this hit */
    uint8_t base_guess;                /* the single BASE0 byte that was active on this hit */
    uint8_t raw[ESB_PROMISC_CAP_LEN];  /* unparsed: leaked address tail + payload, undifferentiated */
} esb_promisc_frame_t;

typedef struct {
    uint32_t slots, blocked, canceled;
    uint32_t hits;                    /* EVENTS_END fired (sync achieved on current guess) */
    uint32_t dropped;                 /* hits lost, ring full */
    uint32_t sig_radio, sig_timer0, idle;
    uint32_t last_rc;
    uint32_t ready_ok, ready_timeout;
    uint32_t guesses_tried;
    uint32_t slot_us;
} esb_promisc_stats_t;

/* Brute-force partial-address ESB/proprietary-PHY sniffer for an UNKNOWN
 * address. Not the nRF24L01+ "illegal address length" quirk (that's a
 * documented hardware quirk of a different, dedicated ESB chip, and nothing
 * confirms it on this chip's RADIO IP block). This is a different, separately
 * documented technique for the nRF5x RADIO peripheral specifically: set
 * PCNF1's BALEN shorter than the real on-air address (here: 1, i.e. match
 * only PREFIX + 1 BASE byte instead of the normal PREFIX + 4 BASE bytes),
 * no length field (PCNF0=0, matching Pacsec/POC||GTFO #17's Micro:bit BLE
 * sniffer config), and CRC disabled -- so the radio syncs on ANY
 * transmission whose first 2 address bytes happen to match our current
 * guess, and the sender's remaining (un-checked) address bytes land at the
 * start of the captured payload instead of being consumed as "address".
 * That register mechanism (BALEN truncation causing a partial match plus
 * leaked remainder) is the part with a real precedent on this RADIO family;
 * porting it from BLE/nRF51 to ESB/nRF52840/Unifying specifically is NOT
 * verified -- treat every capture as a candidate, not a confirmed frame,
 * until checked against a real capture. Two specific unknowns left for that
 * bench check, not asserted here: (1) which byte position in `raw[]` the
 * leaked BASE bytes land at and in what order: (2) whether reducing BALEN
 * behaves identically on this chip's RADIO to the nRF51 case the precedent
 * was built on.
 *
 * Guessing space: PREFIX in [prefix_lo..prefix_hi] (Unifying's documented
 * device-ID range is small -- 0x00 reserved for the dongle, then small
 * increasing values per paired device -- so the realistic range is narrow,
 * not the full 0-255) x BASE guess byte 0..255, one fixed channel. A
 * sustained hit rate at one guess (not a single isolated hit) is the signal
 * to trust; CRC is off, so an isolated hit on random noise is expected and
 * not meaningful on its own.
 */
bool esb_promisc_radio_start(uint8_t channel, uint8_t prefix_lo, uint8_t prefix_hi);
void esb_promisc_radio_stop(void);
bool esb_promisc_radio_running(void);
bool esb_promisc_radio_pop(esb_promisc_frame_t *out);
void esb_promisc_radio_poll(void);
void esb_promisc_radio_get_stats(esb_promisc_stats_t *out);

#endif
