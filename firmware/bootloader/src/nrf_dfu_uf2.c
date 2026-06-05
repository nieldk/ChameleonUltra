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
 *     0x27000 - 0xEF000   Application      <— UF2 writes go here
 *     0xEF000 - 0xFE000   Bootloader       <— do not write
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

#include "crc32.h"
#include "uf2_ghostfat.h"
#include "uf2_blockdev.h"

/* ---- Endpoint plan ----
 * Composite CDC + MSC device. CDC (nrf_dfu_serial_usb.c) owns interfaces
 * 0+1 and EP1/EP2. MSC gets interface 2 and EP3 to avoid conflicts.
 * ----------------------- */
#define MSC_INTERFACE        2
#define MSC_EPIN             NRF_DRV_USBD_EPIN3
#define MSC_EPOUT            NRF_DRV_USBD_EPOUT3
#define MSC_WORKBUFFER_SIZE  512

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
 * MSC must be in the class list before app_usbd_init() is called, because
 * app_usbd_class_append() fails once the stack is running (APP_USBD_POWER_READY
 * has fired and app_usbd_start() has been called by nrf_dfu_serial_usb.c).
 *
 * APP_USBD_MSC_GLOBAL_DEF places the MSC instance in the .usbd_class_inst linker
 * section. app_usbd_init() walks that section and registers every instance it
 * finds — so MSC is enumerated automatically as interface 2 alongside CDC
 * interfaces 0+1, without any runtime class_append() call.
 *
 * uf2_transport_init() therefore has nothing USBD-related to do: CDC owns the
 * stack lifecycle entirely.
 * ----------------------- */

uint32_t uf2_transport_init(nrf_dfu_observer_t observer)
{
    m_observer = observer;
    uf2_ghostfat_init();

    /* USBD stack is owned by nrf_dfu_serial_usb.c. MSC was registered
     * statically via APP_USBD_MSC_GLOBAL_DEF and will be enumerated as
     * interface 2 alongside CDC interfaces 0+1. Nothing to do here. */
    NRF_LOG_INFO("UF2 transport ready. Mount the CHAMELEON drive and drop a .uf2.");
    return NRF_SUCCESS;
}

uint32_t uf2_transport_close(nrf_dfu_transport_t const *p_exception)
{
    (void)p_exception;
    return NRF_SUCCESS;
}
