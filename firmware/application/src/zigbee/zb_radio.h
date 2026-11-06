#ifndef ZB_RADIO_H__
#define ZB_RADIO_H__

#include <stdbool.h>
#include <stdint.h>

#define ZB_MAX_MPDU  125            /* 127 PSDU - 2 FCS */

typedef struct {
    uint8_t channel;                /* channel the frame was received on */
    uint8_t len;                    /* MPDU bytes, FCS not delivered by the radio */
    uint8_t lqi;                    /* raw hardware LQI byte, not converted */
    uint8_t data[ZB_MAX_MPDU];
} zb_frame_t;

typedef struct {
    uint32_t slots;                 /* timeslots granted */
    uint32_t blocked;               /* requests refused by the SoftDevice */
    uint32_t canceled;              /* timeslots taken back */
    uint32_t rx_ok;                 /* frames with a good FCS */
    uint32_t rx_crc;                /* frames with a bad FCS */
    uint32_t dropped;               /* good frames lost, ring full */
    uint8_t  last_lqi;
    uint32_t sig_radio, sig_timer0, idle;   /* callback signals / session idle events */
    uint32_t last_rc;                       /* last sd_radio_request() result in poll */
    uint32_t ed_ok, ed_timeout;             /* energy-detect samples completed / not completed */
    uint8_t  state_end;                     /* NRF_RADIO->STATE just before the slot ended */
    uint32_t ready_ok, ready_timeout;       /* RXEN ramp-up finished / not within 400 us */
    uint8_t  power_was, state_after;        /* RADIO->POWER at slot start, STATE after the ramp wait */
    uint32_t framestart;                    /* length field seen (frame began) */
    uint8_t  ed_max[16];                    /* per channel 11..26: max EDSAMPLE at slot end, raw */
    uint32_t slot_us;               /* length requested for the next slot */
    uint32_t rb_mode, rb_pcnf0, rb_crccnf, rb_freq;  /* registers read straight back after the
                                                        * write, not the values the code assumes */
    uint8_t  rb_sfd;
} zb_stats_t;

/* Passive 802.15.4 RX on channel 11..26, chained SoftDevice timeslots. */
bool zb_radio_start(uint8_t channel);
void zb_radio_set_channel(uint8_t channel);   /* takes effect at the next timeslot */
void zb_radio_stop(void);
bool zb_radio_running(void);
bool zb_radio_pop(zb_frame_t *out);
void zb_radio_poll(void);              /* call periodically from main context */
void zb_radio_get_stats(zb_stats_t *out);

#endif
