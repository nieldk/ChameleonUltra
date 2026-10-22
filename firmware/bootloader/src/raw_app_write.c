#include "raw_app_write.h"

#include <stdbool.h>

#include "uf2_ghostfat.h"      /* UF2_FLASH_APP_START, uf2_flash_write(), uf2_settings_store() */
#include "nrf_dfu_settings.h"
#include "nrf_delay.h"
#include "crc32.h"

/* App area ends at 0xB0000; UF2_FLASH_APP_END also covers staging, log, FDS. */
#define RAW_APP_END  0x000B0000UL
#define PAGE_SIZE    4096UL

static uint32_t m_len, m_crc, m_next;
static bool     m_began;

static raw_app_err_t raw_app_begin(uint32_t len, uint32_t crc32)
{
    m_began = false;
    if (len < 8 || len > (RAW_APP_END - UF2_FLASH_APP_START) || (len & 3u))
    {
        return RAW_APP_ERR_LEN;
    }
    /* Invalidate before the first erase: an interrupted push stays in DFU. */
    s_dfu_settings.bank_0.bank_code = NRF_DFU_BANK_INVALID;
    uf2_settings_store();
    m_len = len; m_crc = crc32; m_next = 0; m_began = true;
    return RAW_APP_OK;
}

static raw_app_err_t raw_app_write(uint32_t offset, uint8_t const * p_data, uint32_t len)
{
    /* Sequential, aligned, in range, and within one 4 KiB page: the flash
     * helper erases a page only when a write starts on its boundary. */
    if (!m_began || offset != m_next || len == 0 || (len & 3u) || len > m_len - offset ||
        ((offset & (PAGE_SIZE - 1)) + len) > PAGE_SIZE)
    {
        return RAW_APP_ERR_LEN;
    }
    if (!uf2_flash_write(UF2_FLASH_APP_START + offset, p_data, len))
    {
        m_began = false;
        return RAW_APP_ERR_LEN;
    }
    m_next += len;
    return RAW_APP_OK;
}

static raw_app_err_t raw_app_commit(uint32_t magic)
{
    uint32_t const * v = (uint32_t const *)UF2_FLASH_APP_START;
    uint32_t sp = v[0], rst = v[1] & ~1u;

    if (magic != RAW_APP_COMMIT_MAGIC)
    {
        return RAW_APP_ERR_MAGIC;
    }
    if (!m_began || m_next != m_len)
    {
        return RAW_APP_ERR_STATE;
    }
    if (crc32_compute((uint8_t const *)UF2_FLASH_APP_START, m_len, NULL) != m_crc)
    {
        return RAW_APP_ERR_CRC;
    }
    /* Vector table sanity: SP in RAM, reset vector inside the image. */
    if (sp <= 0x20000000UL || sp > 0x20040000UL || !(v[1] & 1u) ||
        rst < UF2_FLASH_APP_START || rst >= UF2_FLASH_APP_START + m_len)
    {
        return RAW_APP_ERR_LEN;
    }
    m_began = false;
    s_dfu_settings.bank_0.bank_code  = NRF_DFU_BANK_VALID_APP;
    s_dfu_settings.bank_0.image_size = m_len;
    s_dfu_settings.bank_0.image_crc  = 0;
    uf2_settings_store();
    nrf_delay_ms(100);
    NVIC_SystemReset();
    return RAW_APP_OK;
}

static uint32_t le32(uint8_t const * p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

raw_app_err_t raw_app_handle(uint8_t op, uint8_t const * p, uint16_t n)
{
    if (op == RAW_APP_OP_BEGIN && n == 8)  return raw_app_begin(le32(p), le32(p + 4));
    if (op == RAW_APP_OP_WRITE && n >= 5)  return raw_app_write(le32(p), p + 4, n - 4);
    if (op == RAW_APP_OP_COMMIT && n == 4) return raw_app_commit(le32(p));
    return RAW_APP_ERR_LEN;
}
