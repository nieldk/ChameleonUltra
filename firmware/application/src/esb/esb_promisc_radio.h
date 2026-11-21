#ifndef ESB_PROMISC_RADIO_H__
#define ESB_PROMISC_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#define ESB_PROMISC_CAP_LEN  26u   /* fixed raw-capture length, see esb_promisc_radio.c */

typedef struct {
    uint8_t channel;
    uint8_t prefix_guess;             /* preamble byte matched (0xAA/0x55), not an address guess */
    uint8_t base_guess;                /* unused in preamble-sync (0); kept for log/record compat */
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

/* Preamble-sync ESB/proprietary-PHY sniffer for an UNKNOWN address. Every ESB
 * packet begins with a 1-byte preamble (0xAA or 0x55 depending on the first
 * address bit -- nRF52840 PS, RADIO), so instead of guessing the address we
 * match on that preamble: PCNF0=0 (no length field), CRC off, and PCNF1 BALEN
 * below the legal 2..4 so the match is just the preamble byte. The radio then
 * syncs on EVERY on-air frame and the real address + PCF + payload + CRC land
 * in the fixed-length capture, starting at the address. The host validates the
 * 2-byte ESB CRC-16 over the capture to separate real frames from the many
 * preamble matches on noise (see cli_esb.esb_crc_candidates). The old path
 * guessed PREFIX + 1 BASE byte one value per slot; with a 65536-value space and
 * ~30 ms per guess the right bytes were armed for 30 ms out of a multi-minute
 * sweep, so a real device was effectively never caught.
 *
 * prefix_lo selects the preamble polarity (0 -> 0xAA, non-zero -> 0x55), since a
 * real link uses one phase; flip it if a channel with known traffic stays
 * silent. prefix_hi is kept in the signature for config-blob compatibility but
 * is no longer a guess range. channel 0..100 is the direct 2400+N MHz offset.
 */
bool esb_promisc_radio_start(uint8_t channel, uint8_t prefix_lo, uint8_t prefix_hi);
void esb_promisc_radio_stop(void);
void esb_promisc_radio_set_channel(uint8_t channel);   /* takes effect at the next timeslot */
bool esb_promisc_radio_running(void);
bool esb_promisc_radio_pop(esb_promisc_frame_t *out);
void esb_promisc_radio_poll(void);
void esb_promisc_radio_get_stats(esb_promisc_stats_t *out);

#endif
