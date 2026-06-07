/*
 * nrf_log_backend_cdc.c — NRF_LOG backend writing to a CDC ACM debug port.
 *
 * MIT License.
 */

#include "sdk_common.h"
#if NRF_MODULE_ENABLED(NRF_LOG)

#include "nrf_log_backend_cdc.h"
#include "nrf_log_backend_serial.h"
#include "nrf_log_internal.h"
#include "nrf_log_str_formatter.h"
#include "app_usbd_cdc_acm.h"
#include <string.h>

/* Access debug CDC via getter — direct extern doesn't work because
 * APP_USBD_CDC_ACM_GLOBAL_DEF uses static storage. */
extern app_usbd_cdc_acm_t const *uf2_get_debug_cdc(void);

#define CDC_LOG_BUF_SIZE  256

static uint8_t  m_log_buf[CDC_LOG_BUF_SIZE];
static bool     m_initialized = false;
static bool     m_port_open   = false;

void nrf_log_backend_cdc_port_opened(void)  { m_port_open = true;  }
void nrf_log_backend_cdc_port_closed(void)  { m_port_open = false; }

/* Signature must match nrf_fprintf_fwrite exactly:
 * void (*)(void const * p_user_ctx, char const * p_str, size_t length) */
static void cdc_tx(void const *p_context, char const *p_buf, size_t len)
{
    (void)p_context;
    if (!m_initialized || len == 0) return;
    (void)app_usbd_cdc_acm_write(uf2_get_debug_cdc(),
                                 (const uint8_t *)p_buf, len);
}

static void backend_put(nrf_log_backend_t const *p_backend,
                        nrf_log_entry_t         *p_msg)
{
    nrf_log_backend_serial_put(p_backend, p_msg,
                               m_log_buf, CDC_LOG_BUF_SIZE,
                               cdc_tx);
}

static void backend_flush(nrf_log_backend_t const *p_backend)
{
    (void)p_backend;
}

static void backend_panic_set(nrf_log_backend_t const *p_backend)
{
    (void)p_backend;
}

const nrf_log_backend_api_t nrf_log_backend_cdc_api =
{
    .put       = backend_put,
    .flush     = backend_flush,
    .panic_set = backend_panic_set,
};

void nrf_log_backend_cdc_init(void)
{
    m_initialized = true;
}

void nrf_log_backend_cdc_flush(void)
{
    while (NRF_LOG_PROCESS());
}

#endif /* NRF_MODULE_ENABLED(NRF_LOG) */
