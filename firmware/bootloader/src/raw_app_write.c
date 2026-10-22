#include "raw_app_write.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "uf2_ghostfat.h"      /* UF2_FLASH_APP_START, uf2_flash_write() */
#include "nrf_dfu_settings.h"
#include "nrf_bootloader_info.h"
#include "nrf_nvmc.h"
#include "nrf_delay.h"
#include "crc32.h"

/* The application owns 0x27000-0xB0000 only. UF2_FLASH_APP_END (0xF3000) also
 * covers bl_push staging, the debug log ring and FDS (saved cards/config), so
 * it is NOT a safe limit here. */
#define RAW_APP_END   0x000B0000UL
#define PAGE_SIZE     4096UL

static uint32_t m_len, m_crc, m_next;
static bool     m_began, m_committed;

/* Rewrite settings page + backup; verify both by readback. Returns false on
 * any mismatch so the caller never resets into unverified settings.
 * Power loss inside this function: the other copy is still intact and the
 * bootloader restores from it; at BEGIN the app is still untouched. */
static bool persist_settings(void)
{
    s_dfu_settings.crc = crc32_compute((uint8_t const *)&s_dfu_settings + 4,
                                       offsetof(nrf_dfu_settings_t, init_command) - 4, NULL);
    uint32_t const addr[2] = { BOOTLOADER_SETTINGS_ADDRESS, BOOTLOADER_SETTINGS_BACKUP_ADDRESS };
    for (int i = 0; i < 2; i++)
    {
        nrf_nvmc_page_erase(addr[i]);
        nrf_nvmc_write_bytes(addr[i], (uint8_t const *)&s_dfu_settings, sizeof(nrf_dfu_settings_t));
        if (memcmp((void const *)addr[i], &s_dfu_settings, sizeof(nrf_dfu_settings_t)) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool vector_table_ok(uint32_t len)
{
    uint32_t const * v = (uint32_t const *)UF2_FLASH_APP_START;
    uint32_t sp = v[0], rst = v[1];
    return len >= 8 && sp > 0x20000000UL && sp <= 0x20040000UL && (rst & 1u) &&
           (rst & ~1u) >= UF2_FLASH_APP_START && (rst & ~1u) < (UF2_FLASH_APP_START + len);
}

raw_app_err_t raw_app_begin(uint32_t len, uint32_t crc32)
{
    m_began = false;
    if (len < 8 || len > (RAW_APP_END - UF2_FLASH_APP_START) || (len & 3u))
    {
        return RAW_APP_ERR_LEN;
    }
    /* Mark the app invalid BEFORE the first erase. An interrupted or failed
     * push then leaves the bootloader in DFU mode instead of booting a
     * half-written image. */
    s_dfu_settings.bank_0.bank_code = NRF_DFU_BANK_INVALID;
    if (!persist_settings())
    {
        return RAW_APP_ERR_STATE;
    }
    m_len = len; m_crc = crc32; m_next = 0; m_committed = false; m_began = true;
    return RAW_APP_OK;
}

raw_app_err_t raw_app_write(uint32_t offset, uint8_t const * p_data, uint32_t len)
{
    if (!m_began || m_committed)
    {
        return RAW_APP_ERR_STATE;
    }
    /* Sequential, word aligned, in range (overflow-safe), and never crossing a
     * 4 KiB page: uf2_flash_write() only erases a page when a write STARTS on
     * its boundary, so a crossing write would program un-erased flash. */
    if (offset != m_next || len == 0 || (len & 3u) || len > m_len - offset ||
        ((offset & (PAGE_SIZE - 1)) + len) > PAGE_SIZE)
    {
        return RAW_APP_ERR_LEN;
    }
    if (!uf2_flash_write(UF2_FLASH_APP_START + offset, p_data, len))
    {
        m_began = false;           /* abort; settings already say "invalid" */
        return RAW_APP_ERR_LEN;
    }
    m_next += len;
    return RAW_APP_OK;
}

raw_app_err_t raw_app_commit(uint32_t magic)
{
    if (magic != RAW_APP_COMMIT_MAGIC)
    {
        return RAW_APP_ERR_MAGIC;
    }
    if (!m_began || m_next != m_len || m_committed)
    {
        return RAW_APP_ERR_STATE;
    }
    if (crc32_compute((uint8_t const *)UF2_FLASH_APP_START, m_len, NULL) != m_crc)
    {
        return RAW_APP_ERR_CRC;
    }
    if (!vector_table_ok(m_len))
    {
        return RAW_APP_ERR_LEN;
    }
    m_committed = true;

    /* Mirror uf2_dfu_complete() - diff against it on the real tree. */
    s_dfu_settings.bank_0.bank_code         = NRF_DFU_BANK_VALID_APP;
    s_dfu_settings.bank_0.image_size        = m_len;
    s_dfu_settings.bank_0.image_crc         = 0;
    s_dfu_settings.boot_validation_app.type = NO_VALIDATION;
    s_dfu_settings.boot_validation_crc = crc32_compute(
            (uint8_t const *)&s_dfu_settings.boot_validation_softdevice,
            3u * sizeof(boot_validation_t), NULL);
    if (!persist_settings())
    {
        s_dfu_settings.bank_0.bank_code = NRF_DFU_BANK_INVALID;
        m_committed = false;
        return RAW_APP_ERR_STATE;   /* report failure; do NOT reset */
    }
    nrf_delay_ms(100);
    NVIC_SystemReset();
    return RAW_APP_OK;
}
