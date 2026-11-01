#pragma once
#include <stdint.h>
typedef struct { uint16_t channel_0; uint16_t counter_top; } nrf_pwm_values_wave_form_t;
typedef struct { union { nrf_pwm_values_wave_form_t *p_wave_form; } values; uint16_t length; uint32_t repeats; uint32_t end_delay; } nrf_pwm_sequence_t;
#define NRF_PWM_VALUES_LENGTH(a) ((sizeof(a)) / sizeof(uint16_t))
