/*
 * bl_updater.c — bootloader self-update from the application.
 *
 * Three entry points:
 *   bl_updater_run()                         — replace BL, reset (app stays)
 *                                              [validates CRC first]
 *   bl_updater_run_and_invalidate_app()      — replace BL, erase our own
 *                                              vector table, reset.
 *                                              [validates CRC first]
 *   bl_updater_run_and_invalidate_app_force() — same as above, NO CRC check.
 *                                              For recovery use when the
 *                                              embedded bytes have been
 *                                              verified at build time.
 *
 * RISKS:
 *   - Power loss during BL erase or before BL write completes → bricked
 *     device, recoverable only with SWD.
 *   - The _force variant skips CRC validation. If the embedded blob is
 *     wrong, this WILL brick. Only use when the build-time header has
 *     been independently verified (e.g., manually inspecting CRC32 in
 *     embedded_bootloader.h against the upstream zip's stock BL CRC).
 */

#include "bl_updater.h"
#include "embedded_bootloader.h"

#include <stdint.h>
#include <string.h>

#include "nrf.h"
#include "nrf_sdh.h"
#include "nrf_soc.h"
#include "nrf_delay.h"

#define BL_REGION_START    0x000F3000UL
#define BL_REGION_END      0x000FE000UL
#define BL_PAGE_SIZE       0x1000UL
#define BL_REGION_PAGES    ((BL_REGION_END - BL_REGION_START) / BL_PAGE_SIZE)
#define BL_REGION_BYTES    (BL_REGION_END - BL_REGION_START)

#define APP_REGION_START   0x00027000UL


/* ---- Inline NVMC ---- */

static inline void nvmc_wait_ready(void)
{
    while (NRF_NVMC->READY == NVMC_READY_READY_Busy) { /* spin */ }
}

static void nvmc_page_erase(uint32_t page_addr)
{
    nvmc_wait_ready();
    NRF_NVMC->CONFIG = (NVMC_CONFIG_WEN_Een << NVMC_CONFIG_WEN_Pos);
    nvmc_wait_ready();
    NRF_NVMC->ERASEPAGE = page_addr;
    nvmc_wait_ready();
    NRF_NVMC->CONFIG = (NVMC_CONFIG_WEN_Ren << NVMC_CONFIG_WEN_Pos);
    nvmc_wait_ready();
}

static void nvmc_write_bytes(uint32_t dst, const uint8_t *src, uint32_t len)
{
    nvmc_wait_ready();
    NRF_NVMC->CONFIG = (NVMC_CONFIG_WEN_Wen << NVMC_CONFIG_WEN_Pos);
    nvmc_wait_ready();

    uint32_t remaining = len;
    while (remaining >= 4) {
        uint32_t word;
        memcpy(&word, src, 4);
        *(volatile uint32_t *)dst = word;
        nvmc_wait_ready();
        dst       += 4;
        src       += 4;
        remaining -= 4;
    }
    if (remaining != 0) {
        uint32_t word = 0xFFFFFFFFu;
        memcpy(&word, src, remaining);
        *(volatile uint32_t *)dst = word;
        nvmc_wait_ready();
    }

    NRF_NVMC->CONFIG = (NVMC_CONFIG_WEN_Ren << NVMC_CONFIG_WEN_Pos);
    nvmc_wait_ready();
}


/* CRC32 (zlib polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR). */
static uint32_t crc32_compute(const uint8_t *p, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & -(int32_t)(crc & 1u));
        }
    }
    return ~crc;
}


/* ---- ACL protection ---------------------------------------------------- */
/*
 * The UF2 bootloader calls nrf_bootloader_flash_protect() which sets NRF_ACL
 * regions to prevent writes/erases of the bootloader flash pages. On nRF52840
 * the ACL registers survive soft reset — they remain active when the bootloader
 * jumps to the application. Without clearing them first, nvmc_page_erase() on
 * BL_REGION_START is silently ignored and the old bootloader survives intact.
 */
static void bl_updater_clear_acl(uint32_t start, uint32_t end)
{
    uint32_t n = sizeof(NRF_ACL->ACL) / sizeof(NRF_ACL->ACL[0]);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t acl_start = NRF_ACL->ACL[i].ADDR;
        uint32_t acl_size  = NRF_ACL->ACL[i].SIZE;
        if (acl_size != 0
            && acl_start <  end
            && acl_start + acl_size > start)
        {
            NRF_ACL->ACL[i].SIZE = 0;   /* disable — allows erase/write */
        }
    }
}


bl_updater_status_t bl_updater_validate(void)
{
    if (EMBEDDED_BOOTLOADER_BIN_SIZE == 0u) {
        return BL_UPDATER_ERR_EMPTY;
    }
    if (EMBEDDED_BOOTLOADER_BIN_SIZE > BL_REGION_BYTES) {
        return BL_UPDATER_ERR_TOO_LARGE;
    }
    if (crc32_compute(EMBEDDED_BOOTLOADER_BIN, EMBEDDED_BOOTLOADER_BIN_SIZE)
        != EMBEDDED_BOOTLOADER_BIN_CRC32) {
        return BL_UPDATER_ERR_CRC;
    }
    return BL_UPDATER_OK;
}


/* Core flash operation: disable SD, clear ACL, erase BL pages, write bytes.
 * The `validate_first` flag controls whether we CRC-check first. */
static bl_updater_status_t bl_updater_flash_bl(bool validate_first)
{
    if (validate_first) {
        bl_updater_status_t st = bl_updater_validate();
        if (st != BL_UPDATER_OK) {
            return st;
        }
    } else {
        /* Skip CRC but still sanity-check size to avoid obvious foot-guns */
        if (EMBEDDED_BOOTLOADER_BIN_SIZE == 0u) {
            return BL_UPDATER_ERR_EMPTY;
        }
        if (EMBEDDED_BOOTLOADER_BIN_SIZE > BL_REGION_BYTES) {
            return BL_UPDATER_ERR_TOO_LARGE;
        }
    }

    if (nrf_sdh_is_enabled()) {
        ret_code_t err = nrf_sdh_disable_request();
        if (err != NRF_SUCCESS) {
            return BL_UPDATER_ERR_SD_DISABLE;
        }
        while (nrf_sdh_is_enabled()) { /* observers tear down */ }
    }

    /* Clear any ACL write-protection covering the BL region before we
     * attempt the erase.  The bootloader sets ACL regions to protect itself
     * and these survive soft reset into the application context. */
    bl_updater_clear_acl(BL_REGION_START, BL_REGION_END);

    __disable_irq();

    for (uint32_t i = 0; i < BL_REGION_PAGES; i++) {
        nvmc_page_erase(BL_REGION_START + i * BL_PAGE_SIZE);
    }

    nvmc_write_bytes(BL_REGION_START,
                     EMBEDDED_BOOTLOADER_BIN,
                     EMBEDDED_BOOTLOADER_BIN_SIZE);

    return BL_UPDATER_OK;
}


bl_updater_status_t bl_updater_run(void)
{
    bl_updater_status_t st = bl_updater_flash_bl(true);
    if (st != BL_UPDATER_OK) {
        return st;
    }
    nrf_delay_ms(50);
    NVIC_SystemReset();
    return BL_UPDATER_OK; /* unreached */
}


bl_updater_status_t bl_updater_run_and_invalidate_app(void)
{
    bl_updater_status_t st = bl_updater_flash_bl(true);
    if (st != BL_UPDATER_OK) {
        return st;
    }
    nvmc_page_erase(APP_REGION_START);
    nrf_delay_ms(50);
    NVIC_SystemReset();
    return BL_UPDATER_OK; /* unreached */
}


/* SKIP CRC VALIDATION. Use only when you've already verified the embedded
 * bytes are correct at build time (e.g., by checking
 * EMBEDDED_BOOTLOADER_BIN_CRC32 in the header matches the upstream
 * release's stock BL CRC). */
bl_updater_status_t bl_updater_run_and_invalidate_app_force(void)
{
    bl_updater_status_t st = bl_updater_flash_bl(false);
    if (st != BL_UPDATER_OK) {
        return st;
    }
    nvmc_page_erase(APP_REGION_START);
    nrf_delay_ms(50);
    NVIC_SystemReset();
    return BL_UPDATER_OK; /* unreached */
}
