#include "bl_egg.h"

#include "bl_info.h"
#include "hw_connect.h"
#include "nrf_delay.h"
#include "nrf_gpio.h"

extern const bl_info_t g_bl_info;

static void leds_set(uint32_t mask)
{
    uint32_t *led = hw_get_led_array();
    for (uint32_t i = 0; i < RGB_LIST_NUM; i++) {
        if (mask & (1u << i)) {
            nrf_gpio_pin_set(led[i]);
        } else {
            nrf_gpio_pin_clear(led[i]);
        }
    }
}

void bl_egg_play(void)
{
    uint32_t all = (1u << RGB_LIST_NUM) - 1u;

    set_slot_light_color(RGB_RED);
    for (int pass = 0; pass < 2; pass++) {
        for (uint32_t i = 0; i < RGB_LIST_NUM; i++) {
            leds_set(1u << i);
            nrf_delay_ms(60);
        }
        for (uint32_t i = RGB_LIST_NUM - 1; i > 0; i--) {
            leds_set(1u << (i - 1));
            nrf_delay_ms(60);
        }
    }
    /* Alternate halves, not all LEDs at once: lighting every slot LED together
     * may draw too much current on a weak supply. */
    for (int bark = 0; bark < 3; bark++) {
        leds_set(0x55555555u & all);
        nrf_delay_ms(80);
        leds_set(0xAAAAAAAAu & all);
        nrf_delay_ms(80);
        leds_set(0);
        nrf_delay_ms(60);
    }
    set_slot_light_color(RGB_GREEN);
    leds_set(g_bl_info.version & all);
    nrf_delay_ms(1200);
    leds_set(0);
}
