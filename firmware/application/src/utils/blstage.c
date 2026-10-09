#include "blstage.h"

#include <string.h>

#include "app_timer.h"
#include "bsp_wdt.h"
#include "logflash.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "nrf_mbr.h"
#include "nrf_soc.h"
#include "nrf_sdm.h"

#define NRF_LOG_MODULE_NAME blstage
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

#define BL_ADDR         0x000F3000UL
#define PAGE_SIZE       4096UL
#define WAIT_US         5000000UL
#define APPLY_DELAY_MS  300

static void bs_evt(nrf_fstorage_evt_t *p_evt);

NRF_FSTORAGE_DEF(nrf_fstorage_t m_bs_fs) = {
    .evt_handler = bs_evt,
    .start_addr  = BLSTAGE_BASE,
    .end_addr    = BLSTAGE_BASE + BLSTAGE_AREA,
};

APP_TIMER_DEF(m_apply_timer);

static volatile bool m_done;
static volatile ret_code_t m_res;
static bool m_inited;
static bool m_began;
static bool m_committed;
static uint32_t m_len, m_crc, m_next;
static uint32_t m_buf[BLSTAGE_CHUNK_MAX / 4];

static void bs_evt(nrf_fstorage_evt_t *p_evt) {
    m_res = p_evt->result;
    m_done = true;
}

static bool wait_done(void) {
    for (uint32_t t = 0; !m_done; t += 100) {
        if (t >= WAIT_US) {
            return false;
        }
        bsp_wdt_feed();
        nrf_delay_us(100);
    }
    return m_res == NRF_SUCCESS;
}

static uint32_t crc32_flash(uint32_t addr, uint32_t len) {
    const uint8_t *p = (const uint8_t *)addr;
    uint32_t c = 0xFFFFFFFFu;
    while (len--) {
        c ^= *p++;
        for (int i = 0; i < 8; i++) {
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
        }
    }
    return ~c;
}

static bool mbr_ready(bls_err_t *err) {
    uint32_t bl = *(volatile uint32_t *)MBR_BOOTLOADER_ADDR;
    if (bl == 0xFFFFFFFFu) {
        bl = *(volatile uint32_t *)MBR_UICR_BOOTLOADER_ADDR;
    }
    if (bl != BL_ADDR) {
        *err = BLS_ERR_NO_BLADDR;
        return false;
    }
    if (*(volatile uint32_t *)MBR_PARAM_PAGE_ADDR == 0xFFFFFFFFu &&
            *(volatile uint32_t *)MBR_UICR_PARAM_PAGE_ADDR == 0xFFFFFFFFu) {
        *err = BLS_ERR_NO_PARAM;
        return false;
    }
    return true;
}

bls_err_t blstage_begin(uint32_t len, uint32_t crc32) {
    bls_err_t err;
    m_began = false;
    if (len < 64 || len > BLSTAGE_MAX_LEN || (len & 3u)) {
        return BLS_ERR_LEN;
    }
    if (!mbr_ready(&err)) {
        return err;
    }
    if (!m_inited) {
        if (nrf_fstorage_init(&m_bs_fs, &nrf_fstorage_sd, NULL) != NRF_SUCCESS) {
            return BLS_ERR_FLASH;
        }
        m_inited = true;
    }
    uint32_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    m_done = false;
    if (nrf_fstorage_erase(&m_bs_fs, BLSTAGE_BASE, pages, NULL) != NRF_SUCCESS || !wait_done()) {
        return BLS_ERR_FLASH;
    }
    m_len = len;
    m_crc = crc32;
    m_next = 0;
    m_began = true;
    return BLS_OK;
}

bls_err_t blstage_write(uint32_t offset, const uint8_t *data, uint32_t len) {
    if (!m_began || m_committed) {
        return BLS_ERR_STATE;
    }
    if (offset != m_next || len == 0 || len > BLSTAGE_CHUNK_MAX || (len & 3u) || offset + len > m_len) {
        return BLS_ERR_LEN;
    }
    memcpy(m_buf, data, len);
    m_done = false;
    if (nrf_fstorage_write(&m_bs_fs, BLSTAGE_BASE + offset, m_buf, len, NULL) != NRF_SUCCESS || !wait_done()) {
        return BLS_ERR_FLASH;
    }
    m_next += len;
    return BLS_OK;
}

static void apply(void *ctx) {
    while (NRF_LOG_PROCESS());
    logflash_flush_blocking(100);
    bsp_wdt_feed();
    sd_softdevice_disable();
    sd_mbr_command_t cmd = {
        .command = SD_MBR_COMMAND_COPY_BL,
        .params.copy_bl.bl_src = (uint32_t *)BLSTAGE_BASE,
        .params.copy_bl.bl_len = m_len / 4,
    };
    sd_mbr_command(&cmd);
    /* Only reached on error: restart the app. */
    NVIC_SystemReset();
}

bls_err_t blstage_commit(uint32_t magic) {
    if (magic != BLSTAGE_COMMIT_MAGIC) {
        return BLS_ERR_MAGIC;
    }
    if (!m_began || m_next != m_len || m_committed) {
        return BLS_ERR_STATE;
    }
    if (crc32_flash(BLSTAGE_BASE, m_len) != m_crc) {
        return BLS_ERR_CRC;
    }
    const uint32_t *v = (const uint32_t *)BLSTAGE_BASE;
    if (v[0] < 0x20000000UL || v[0] > 0x20040000UL || !(v[1] & 1u) ||
            (v[1] & ~1u) < BL_ADDR || (v[1] & ~1u) >= BL_ADDR + BLSTAGE_MAX_LEN) {
        return BLS_ERR_IMAGE;
    }
    NRF_LOG_INFO("blstage: %u bytes staged, crc ok, copying in %d ms", m_len, APPLY_DELAY_MS);
    m_committed = true;
    if (app_timer_create(&m_apply_timer, APP_TIMER_MODE_SINGLE_SHOT, apply) != NRF_SUCCESS ||
            app_timer_start(m_apply_timer, APP_TIMER_TICKS(APPLY_DELAY_MS), NULL) != NRF_SUCCESS) {
        m_committed = false;
        return BLS_ERR_STATE;
    }
    return BLS_OK;
}
