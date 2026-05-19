/*
 * nrf_dfu_uf2.c — Nordic SDK DFU transport for UF2 drag-and-drop updates.
 *
 * Coexists with nrf_dfu_serial_usb.c (CDC) by piggy-backing on whichever
 * transport initialises the USBD stack first. The MSC interface gets
 * appended as a second USB class, producing a composite CDC + MSC device.
 *
 * Writes to flash from the bootloader context are safe because the
 * bootloader is not executing from the app region. We bypass
 * nrf_dfu_validation entirely — this transport accepts UNSIGNED images
 * by design (UF2 has no signature). The legacy CDC + BLE DFU transports
 * still go through full signature validation.
 *
 * Memory layout:
 *     0x00000 - 0x01000   MBR
 *     0x01000 - 0x27000   SoftDevice S140
 *     0x27000 - 0xF3000   Application      <— UF2 writes go here
 *     0xF3000 - 0xFE000   Bootloader       <— do not write
 *     0xFE000 - 0xFF000   MBR params
 *     0xFF000 - 0x100000  Bootloader settings
 *
 * MIT License.
 */

#include <string.h>

#include "nrf_dfu_transport.h"
#include "nrf_dfu_settings.h"
#include "nrf_dfu_types.h"
#include "nrf_bootloader_info.h"
#include "nrf_nvmc.h"
#include "nrf_delay.h"
#include "app_usbd.h"
#include "app_usbd_core.h"
#include "app_usbd_msc.h"
#include "app_usbd_string_desc.h"
#include "app_usbd_serial_num.h"
#include "app_scheduler.h"
#include "nrf_drv_clock.h"
#include "nrf_drv_power.h"

#define NRF_LOG_MODULE_NAME nrf_dfu_uf2
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#include "uf2.h"
#include "uf2_ghostfat.h"
#include "uf2_blockdev.h"

/* ---- Endpoint plan ----
 * The CDC ACM transport in nrf_dfu_serial_usb.c uses:
 *     interface 0   EPIN2          (COMM)
 *     interface 1   EPIN1, EPOUT1  (DATA)
 * Pick clear endpoints for MSC:
 *     interface 2   EPIN3, EPOUT2
 * ----------------------- */
#define MSC_INTERFACE        2
#define MSC_EPIN             NRF_DRV_USBD_EPIN3
#define MSC_EPOUT            NRF_DRV_USBD_EPOUT2
#define MSC_WORKBUFFER_SIZE  1024

static nrf_dfu_observer_t m_observer;

/* Forward decls for transport registration */
static uint32_t uf2_transport_init(nrf_dfu_observer_t observer);
static uint32_t uf2_transport_close(nrf_dfu_transport_t const *p_exception);

DFU_TRANSPORT_REGISTER(nrf_dfu_transport_t const uf2_dfu_transport) =
{
    .init_func  = uf2_transport_init,
    .close_func = uf2_transport_close,
};

/* MSC user event handler — required by the SDK macro but we don't need
 * to react to anything specific. ghostfat handles all the actual logic. */
static void msc_user_ev_handler(app_usbd_class_inst_t const *p_inst,
                                app_usbd_msc_user_event_t event)
{
    (void)p_inst; (void)event;
}

/* MSC class instance — single LUN backed by uf2_blockdev. */
APP_USBD_MSC_GLOBAL_DEF(m_app_msc,
                        MSC_INTERFACE,
                        msc_user_ev_handler,
                        APP_USBD_MSC_EPIN_EPOUT(MSC_EPIN, MSC_EPOUT),
                        (&uf2_blockdev),
                        MSC_WORKBUFFER_SIZE);

/* ---- ghostfat -> flash glue ---- */

void uf2_flash_read(uint32_t addr, void *buf, uint32_t len)
{
    if (addr >= UF2_FLASH_APP_START && addr + len <= UF2_FLASH_APP_END) {
        memcpy(buf, (const void *)addr, len);
    } else {
        memset(buf, 0xFF, len);
    }
}

void uf2_flash_write(uint32_t addr, const void *data, uint32_t len)
{
    /* Belt and braces — ghostfat already guards this. */
    if (addr < UF2_FLASH_APP_START || addr + len > UF2_FLASH_APP_END) {
        NRF_LOG_WARNING("UF2 write outside app region 0x%08x (%u)", addr, len);
        return;
    }

    const uint32_t page = NRF_FICR->CODEPAGESIZE;  /* 4096 on nRF52840 */
    if ((addr & (page - 1)) == 0) {
        nrf_nvmc_page_erase(addr);
    }
    nrf_nvmc_write_bytes(addr, (const uint8_t *)data, len);

    if (m_observer) m_observer(NRF_DFU_EVT_OBJECT_RECEIVED);
}

void uf2_dfu_complete(void)
{
    NRF_LOG_INFO("UF2 transfer complete (%u blocks)",
                 uf2_ghostfat_blocks_written());

    /* Mark application bank valid so the bootloader will boot it. */
    s_dfu_settings.bank_0.bank_code  = NRF_DFU_BANK_VALID_APP;
    s_dfu_settings.bank_0.image_size = UF2_FLASH_APP_SIZE;
    s_dfu_settings.bank_0.image_crc  = 0;  /* 0 = skip CRC check */
    (void)nrf_dfu_settings_write_and_backup(NULL);

    if (m_observer) m_observer(NRF_DFU_EVT_DFU_COMPLETED);

    /* Let the SCSI response drain before we reset. */
    nrf_delay_ms(150);
    NVIC_SystemReset();
}

/* ---- USBD wiring ---- */

static void usbd_event_handler(app_usbd_event_type_t event)
{
    switch (event) {
        case APP_USBD_EVT_DRV_SUSPEND:    app_usbd_suspend_req();  break;
        case APP_USBD_EVT_DRV_RESUME:                              break;
        case APP_USBD_EVT_STARTED:                                 break;
        case APP_USBD_EVT_STOPPED:        app_usbd_disable();      break;
        case APP_USBD_EVT_POWER_DETECTED:
            if (!nrf_drv_usbd_is_enabled()) app_usbd_enable();
            break;
        case APP_USBD_EVT_POWER_REMOVED:  app_usbd_stop();         break;
        case APP_USBD_EVT_POWER_READY:    app_usbd_start();        break;
        default: break;
    }
}

static uint32_t uf2_transport_init(nrf_dfu_observer_t observer)
{
    ret_code_t err;

    m_observer = observer;
    uf2_ghostfat_init();

    /* nrf_dfu_serial_usb.c will normally have run first and already
     * initialised these subsystems. Tolerate "already initialised". */
    static const app_usbd_config_t usbd_config = {
        .ev_state_proc = usbd_event_handler,
    };

    err = nrf_drv_clock_init();
    if (err != NRF_SUCCESS && err != NRF_ERROR_MODULE_ALREADY_INITIALIZED) {
        return err;
    }

    err = nrf_drv_power_init(NULL);
    if (err != NRF_SUCCESS && err != NRF_ERROR_MODULE_ALREADY_INITIALIZED) {
        return err;
    }

    app_usbd_serial_num_generate();

    err = app_usbd_init(&usbd_config);
    if (err != NRF_SUCCESS && err != NRF_ERROR_INVALID_STATE) {
        /* INVALID_STATE = serial-USB DFU transport already brought USBD up.
         * Anything else is fatal. */
        return err;
    }

    err = app_usbd_class_append(app_usbd_msc_class_inst_get(&m_app_msc));
    if (err != NRF_SUCCESS) {
        NRF_LOG_ERROR("MSC class append failed: 0x%08x", err);
        return err;
    }

    /* If we initialised USBD ourselves, also kick power-event handling.
     * If serial-USB already did, this returns INVALID_STATE which we ignore. */
    err = app_usbd_power_events_enable();
    if (err != NRF_SUCCESS && err != NRF_ERROR_INVALID_STATE) {
        return err;
    }

    NRF_LOG_INFO("UF2 transport ready. Mount the CHAMELEON drive and drop a .uf2.");
    return NRF_SUCCESS;
}

static uint32_t uf2_transport_close(nrf_dfu_transport_t const *p_exception)
{
    (void)p_exception;
    /* MSC class stays appended — nothing to tear down explicitly. */
    return NRF_SUCCESS;
}
