/*
 * Host test: FDX-B modulator -> edge intervals -> real fdxb decoder.
 * Compiles protocols/fdxb.c and utils/diphase.c against stub SDK headers.
 * Build/run: make -C tests
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "protocols/fdxb.c"
#include "utils/diphase.c"

#define CARRIER_CYCLES_PER_US 0.1342  /* 134.2 kHz */

/* Replay the PWM sequence `loops` times and count frames the decoder accepts. */
static int roundtrip(const uint8_t *frame, int loops) {
    void *c = fdxb.alloc();
    fdxb.decoder.start(c, 0);
    const nrf_pwm_sequence_t *seq = fdxb.modulator(c, (uint8_t *)frame);
    int n = seq->length / 2;  /* length counts uint16 values, 2 per entry */
    double t = 0, last_rise = -1;
    bool prev = false;
    int ok = 0;
    for (int l = 0; l < loops; l++) {
        for (int i = 0; i < n; i++) {
            nrf_pwm_values_wave_form_t v = seq->values.p_wave_form[i];
            bool lvl = v.channel_0 != 0;
            if (lvl && !prev) {
                if (last_rise >= 0) {
                    uint16_t cycles = (uint16_t)((t - last_rise) * CARRIER_CYCLES_PER_US + 0.5);
                    if (fdxb.decoder.feed(c, cycles)) {
                        if (memcmp(fdxb.get_data(c), frame, FDXB_DATA_SIZE) == 0) {
                            ok++;
                        }
                        fdxb.decoder.start(c, 0);
                    }
                }
                last_rise = t;
            }
            prev = lvl;
            t += v.counter_top;
        }
    }
    fdxb.free(c);
    return ok;
}

int main(void) {
    int fail = 0;
    /* default slot frame: country 999, national 1, animal flag */
    const uint8_t def[13] = {0x01, 0x00, 0x00, 0x00, 0xC0, 0xF9, 0x00, 0x80, 0x44, 0x2E, 0x00, 0x00, 0x00};
    if (fdxb_crc16(def, 8) != 0x2E44) {
        printf("FAIL default frame CRC\n");
        fail++;
    }
    if (roundtrip(def, 6) < 3) {
        printf("FAIL default frame\n");
        fail++;
    }
    /* random frames, both zero-count parities occur; reserved bits 49-62 zero */
    srand(1);
    for (int k = 0; k < 500; k++) {
        uint8_t f[13];
        for (int i = 0; i < 13; i++) {
            f[i] = (uint8_t)rand();
        }
        f[6] &= 0x01;
        f[7] &= 0x80;
        uint16_t crc = fdxb_crc16(f, 8);
        f[8] = crc & 0xFF;
        f[9] = crc >> 8;
        if (roundtrip(f, 6) < 3) {
            printf("FAIL random frame %d\n", k);
            fail++;
            break;
        }
    }
    printf(fail ? "FAILED\n" : "OK\n");
    return fail;
}
