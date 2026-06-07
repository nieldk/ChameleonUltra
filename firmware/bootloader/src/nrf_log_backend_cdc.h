/*
 * nrf_log_backend_cdc.h — NRF_LOG backend that writes to a CDC ACM
 * USB serial port (the debug port, interfaces 3+4 on the composite device).
 *
 * MIT License.
 */

#ifndef NRF_LOG_BACKEND_CDC_H
#define NRF_LOG_BACKEND_CDC_H

#include "nrf_log_backend_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const nrf_log_backend_api_t nrf_log_backend_cdc_api;

/* Initialise the CDC debug backend. Must be called after the CDC ACM
 * debug class instance has been appended to the USBD stack. */
void nrf_log_backend_cdc_init(void);

/* Called from the CDC ACM user event handler in nrf_dfu_uf2.c
 * to gate writes based on host port open/close state. */
void nrf_log_backend_cdc_port_opened(void);
void nrf_log_backend_cdc_port_closed(void);

/* Flush any buffered log data — call periodically from the main loop
 * or from the scheduler to drain the log queue. */
void nrf_log_backend_cdc_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* NRF_LOG_BACKEND_CDC_H */
