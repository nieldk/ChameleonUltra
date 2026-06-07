/*
 * nrf_dfu_uf2.c — Nordic SDK DFU transport for UF2 drag-and-drop updates.
 *
 * Composite USB device: CDC ACM (DFU serial) + MSC (UF2) + CDC ACM (debug log).
 *   Interface 0+1  EP1/EP2  — CDC ACM DFU serial (nrf_dfu_serial_usb.c)
 *   Interface 2    EP3      — MSC UF2 drag-and-drop
 *   Interface 3+4  EP4/EP5  — CDC ACM debug log output (TX only)
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
 *     0x27000 - 0xEB000   Application      <— UF2 writes go here
 *     0xEB000 - 0xFE000   Bootloader       <— do not write
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
#include "app_usbd_cdc_acm.h"
#include "app_usbd_string_desc.h"
#include "app_usbd_serial_num.h"
#include "app_scheduler.h"
#include "nrf_drv_clock.h"
#include "nrf_drv_power.h"
#include "nrf_log_backend_cdc.h"
#include "nrf_log_ctrl.h"

#define NRF_LOG_MODULE_NAME nrf_dfu_uf2
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#include "crc32.h"
#include "uf2_ghostfat.h"
#include "uf2_blockdev.h"

/* ---- Endpoint plan ----
 * Composite CDC(DFU) + MSC(UF2) + CDC(debug) device:
 *   CDC DFU  : interfaces 0+1, EP1/EP2  — owned by nrf_dfu_serial_usb.c
 *   MSC      : interface  2,   EP3      — UF2 drag-and-drop
 *   CDC debug: interfaces 3+4, EP4/EP5  — TX-only log output
 * ----------------------- */
#define MSC_INTERFACE        2
#define MSC_EPIN             NRF_DRV_USBD_EPIN3
#define MSC_EPOUT            NRF_DRV_USBD_EPOUT3
#define MSC_WORKBUFFER_SIZE  512

#define DBG_CDC_COMM_INTERFACE   3
#define DBG_CDC_COMM_EPIN        NRF_DRV_USBD_EPIN5
#define DBG_CDC_DATA_INTERFACE   4
#define DBG_CDC_DATA_EPIN        NRF_DRV_USBD_EPIN4
#define DBG_CDC_DATA_EPOUT       NRF_DRV_USBD_EPOUT4

static nrf_dfu_observer_t m_observer;

/* Forward decls for transport registration. Marked non-static + used so
 * LTO can't drop them — their addresses end up in a section-variable that
 * the bootloader walks at runtime; the dataflow isn't visible at the IR
 * level so LTO needs explicit hints. */
uint32_t uf2_transport_init(nrf_dfu_observer_t observer)         __attribute__((used));
uint32_t uf2_transport_close(nrf_dfu_transport_t const *p_excpt) __attribute__((used));

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
                        (MSC_EPIN, MSC_EPOUT),
                        (&uf2_blockdev),
                        MSC_WORKBUFFER_SIZE);

/* ---- Debug CDC ACM (TX only, log output) ---- */

static void debug_cdc_user_ev_handler(app_usbd_class_inst_t const *p_inst,
                                      app_usbd_cdc_acm_user_event_t event)
{
    switch (event)
    {
        case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN:
            nrf_log_backend_cdc_port_opened();
            break;
        case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
            nrf_log_backend_cdc_port_closed();
            break;
        default:
            break;
    }
}

APP_USBD_CDC_ACM_GLOBAL_DEF(m_app_cdc_debug,
                            debug_cdc_user_ev_handler,
                            DBG_CDC_COMM_INTERFACE,
                            DBG_CDC_DATA_INTERFACE,
                            DBG_CDC_COMM_EPIN,
                            DBG_CDC_DATA_EPIN,
                            DBG_CDC_DATA_EPOUT,
                            APP_USBD_CDC_COMM_PROTOCOL_NONE);

/* Log backend instance — registered with NRF_LOG at init time. */
NRF_LOG_BACKEND_DEF(m_cdc_log_backend, nrf_log_backend_cdc_api, NULL);

/* ---- ghostfat -> flash glue ---- */

void uf2_flash_read(uint32_t addr, void *buf, uint32_t len)
{
    if (addr >= UF2_FLASH_APP_START && addr + len <= UF2_FLASH_APP_END) {
        memcpy(buf, (const void *)addr, len);
    } else {
        memset(buf, 0xFF, len);
    }
}

bool uf2_flash_write(uint32_t addr, const void *data, uint32_t len)
{
    if (addr < UF2_FLASH_APP_START || addr + len > UF2_FLASH_APP_END) {
        NRF_LOG_WARNING("UF2 write outside app region 0x%08x", addr);
        return false;
    }

    const uint32_t page = NRF_FICR->CODEPAGESIZE;
    if ((addr & (page - 1)) == 0) {
        nrf_nvmc_page_erase(addr);
        /* Verify erase — if flash is stuck low it won't clear. */
        const uint32_t *p = (const uint32_t *)addr;
        for (uint32_t i = 0; i < page / 4; i++) {
            if (p[i] != 0xFFFFFFFF) return false;
        }
    }
    nrf_nvmc_write_bytes(addr, (const uint8_t *)data, len);

    if (m_observer) m_observer(NRF_DFU_EVT_OBJECT_RECEIVED);
    return true;
}

/* ---- DFU completion ---- */

void uf2_dfu_complete(void)
{
    NRF_LOG_INFO("UF2 transfer complete (%u blocks)",
                 uf2_ghostfat_blocks_written());

    /* Mark application bank valid so the bootloader will boot it on the
     * next reset.  image_size reflects actual bytes written; image_crc = 0
     * skips the CRC check on next boot. */
    s_dfu_settings.bank_0.bank_code  = NRF_DFU_BANK_VALID_APP;
    s_dfu_settings.bank_0.image_size = uf2_ghostfat_blocks_written() * 256u;
    s_dfu_settings.bank_0.image_crc  = 0;

    /* Compute settings CRC exactly as the SDK does in settings_crc_get():
     * CRC32 over bytes [4 .. offsetof(init_command)) of the settings struct.
     * Using sizeof() instead would include the init_command blob and produce
     * a different value, causing the bootloader to reject the settings. */
    s_dfu_settings.crc = crc32_compute(
        (uint8_t const *)&s_dfu_settings + 4,
        offsetof(nrf_dfu_settings_t, init_command) - 4,
        NULL);

    /* Write settings synchronously via NVMC — no scheduler, no callbacks,
     * no race with NVIC_SystemReset(). The old settings written by
     * nrfutil settings generate contain a non-zero image_crc for the
     * previous app; if those survive the UF2 flash the bootloader's CRC
     * check will fail and it will re-enter DFU instead of booting the
     * new app. Direct NVMC writes guarantee the new settings are on flash
     * before the reset fires. */
    nrf_nvmc_page_erase(BOOTLOADER_SETTINGS_ADDRESS);
    nrf_nvmc_write_bytes(BOOTLOADER_SETTINGS_ADDRESS,
                         (const uint8_t *)&s_dfu_settings,
                         sizeof(nrf_dfu_settings_t));

    nrf_nvmc_page_erase(BOOTLOADER_SETTINGS_BACKUP_ADDRESS);
    nrf_nvmc_write_bytes(BOOTLOADER_SETTINGS_BACKUP_ADDRESS,
                         (const uint8_t *)&s_dfu_settings,
                         sizeof(nrf_dfu_settings_t));

    if (m_observer) m_observer(NRF_DFU_EVT_DFU_COMPLETED);

    nrf_delay_ms(100);
    NVIC_SystemReset();
}

/* ---- USBD wiring ----
 *
 * nrf_dfu_serial_usb.c owns the USBD stack lifecycle. It calls the weak
 * usb_dfu_transport_class_register() hook after app_usbd_init() but before
 * app_usbd_power_events_enable() — the only safe window to append a class.
 * We implement that hook here to register MSC as interface 2.
 * ----------------------- */

static int32_t m_backend_id = -99;

void usb_dfu_transport_class_register(void)
{
    ret_code_t err;

    err = app_usbd_class_append(app_usbd_msc_class_inst_get(&m_app_msc));
    if (err != NRF_SUCCESS) {
        NRF_LOG_ERROR("MSC class append failed: 0x%08x", err);
    } else {
        NRF_LOG_INFO("MSC class registered as interface 2.");
    }

    err = app_usbd_class_append(app_usbd_cdc_acm_class_inst_get(&m_app_cdc_debug));
    if (err != NRF_SUCCESS) {
        NRF_LOG_ERROR("Debug CDC class append failed: 0x%08x", err);
    } else {
        NRF_LOG_INFO("Debug CDC registered as interfaces 3+4.");
    }

    /* Register and enable the CDC log backend. */
    nrf_log_backend_cdc_init();
    m_backend_id = nrf_log_backend_add(&m_cdc_log_backend, NRF_LOG_SEVERITY_DEBUG);
    if (m_backend_id >= 0) {
        nrf_log_backend_enable(&m_cdc_log_backend);
    }
}

/* Accessor for the debug CDC instance — used by main.c for direct writes.
 * Needed because APP_USBD_CDC_ACM_GLOBAL_DEF uses static storage, so the
 * instance cannot be extern'd directly across translation units. */
app_usbd_cdc_acm_t const *uf2_get_debug_cdc(void)
{
    return &m_app_cdc_debug;
}

uint32_t uf2_transport_init(nrf_dfu_observer_t observer)
{
    m_observer = observer;
    uf2_ghostfat_init();

    /* USBD stack and MSC registration are handled via the weak hook above.
     * CDC (nrf_dfu_serial_usb.c) owns the stack lifecycle. */
    NRF_LOG_INFO("UF2 transport ready. Mount the CHAMELEON drive and drop a .uf2.");
    return NRF_SUCCESS;
}

uint32_t uf2_transport_close(nrf_dfu_transport_t const *p_exception)
{
    (void)p_exception;
    return NRF_SUCCESS;
}
