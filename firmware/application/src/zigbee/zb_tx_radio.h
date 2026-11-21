#ifndef ZB_TX_RADIO_H__
#define ZB_TX_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#define ZB_TX_MAX_PSDU 125u    /* frame bytes excluding the 2-byte FCS the radio adds */

typedef struct {
    uint32_t slots, blocked, canceled, idle;
    uint32_t tx_attempts;      /* TXEN issued */
    uint32_t tx_done;          /* EVENTS_END after a TX */
    uint32_t tx_timeout;
    uint32_t sent;             /* repeats transmitted */
    uint32_t last_rc;
    uint32_t slot_us;
} zb_tx_stats_t;

/* Transmit a raw IEEE 802.15.4 frame (MAC bytes without FCS) on a Zigbee
 * channel (11..26), `repeat` times, under chained SoftDevice timeslots. The
 * radio adds the 2-byte FCS (PHR length = frame_len + 2, CRCINC). PHY config
 * matches zb_radio.c (Ieee802154_250Kbit, SFD 0xA7, CRC 0x11021/0). No CSMA/CCA
 * -- a straight inject; the caller owns the frame (e.g. a NWK-secured Leave
 * built host-side). Returns false on a bad argument or if a session is open.
 */
bool zb_tx_radio_start(uint8_t channel, const uint8_t *frame, uint8_t frame_len,
                       uint8_t repeat, uint8_t gap_ms);
bool zb_tx_radio_running(void);
bool zb_tx_radio_done(void);
void zb_tx_radio_poll(void);
void zb_tx_radio_stop(void);
void zb_tx_radio_get_stats(zb_tx_stats_t *out);

#endif
