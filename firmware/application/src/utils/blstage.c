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
#define MBR_PARAM_PAGE  0x000FE000UL   /* NRFFW[1] target; just past the BL region */
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
    m_began = false;
    if (len < 64 || len > BLSTAGE_MAX_LEN || (len & 3u)) {
        return BLS_ERR_LEN;
    }
    /* The MBR-registration check lives in blstage_commit (the COPY_BL path), not
     * here: blstage_commit_raw deliberately runs on devices that fail it, since
     * it registers the bootloader itself. Staging is the same for both. */
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
    uint32_t rc = sd_mbr_command(&cmd);
    /* Only reached on error: keep the code in the RAM log, restart the app. */
    NRF_LOG_ERROR("blstage: COPY_BL failed, rc=0x%x", rc);
    while (NRF_LOG_PROCESS());
    NVIC_SystemReset();
}

/* True if an ACL region with write/erase blocked overlaps [addr, addr+len).
 * ACL is tighten-only and re-armed every boot, so a locked bootloader region
 * cannot be written from the app by any means (raw NVMC or MBR COPY_BL). */
static bool bl_acl_write_locked(uint32_t addr, uint32_t len) {
    for (int i = 0; i < 8; i++) {
        uint32_t a = NRF_ACL->ACL[i].ADDR;
        uint32_t s = NRF_ACL->ACL[i].SIZE;
        if (s == 0) {
            continue;
        }
        if (!((NRF_ACL->ACL[i].PERM >> ACL_ACL_PERM_WRITE_Pos) & 1u)) {
            continue;   /* this region does not block writes */
        }
        if (addr < a + s && a < addr + len) {
            return true;
        }
    }
    return false;
}

static bls_err_t verify_staged(void) {
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
    return BLS_OK;
}

static bls_err_t schedule_apply(app_timer_timeout_handler_t fn) {
    m_committed = true;
    if (app_timer_create(&m_apply_timer, APP_TIMER_MODE_SINGLE_SHOT, fn) != NRF_SUCCESS ||
            app_timer_start(m_apply_timer, APP_TIMER_TICKS(APPLY_DELAY_MS), NULL) != NRF_SUCCESS) {
        m_committed = false;
        return BLS_ERR_STATE;
    }
    return BLS_OK;
}

bls_err_t blstage_commit(uint32_t magic) {
    if (magic != BLSTAGE_COMMIT_MAGIC) {
        return BLS_ERR_MAGIC;
    }
    bls_err_t e = verify_staged();
    if (e != BLS_OK) {
        return e;
    }
    if (bl_acl_write_locked(BL_ADDR, m_len)) {
        return BLS_ERR_ACL_LOCKED;
    }
    /* COPY_BL needs the MBR registration; raw commit does not. */
    if (!mbr_ready(&e)) {
        return e;
    }
    NRF_LOG_INFO("blstage: %u bytes staged, crc ok, copying in %d ms", m_len, APPLY_DELAY_MS);
    return schedule_apply(apply);
}

/* Set the NVMC write/erase mode and wait until the controller is ready. The
 * nRF52840 does not allow a direct Een<->Wen switch, so every phase below ends
 * back at Ren before the next sets the mode it needs. */
static inline void nvmc_mode(uint32_t wen) {
    NRF_NVMC->CONFIG = (wen << NVMC_CONFIG_WEN_Pos);
    while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
}

static inline void nvmc_settle(void) {
    while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
}

/* Raw installer: no MBR, no journaling. Runs from the app region (0x27000), so
 * erasing the bootloader region does not erase the code doing it; the busy
 * loops read the NVMC register, and instruction fetches simply stall while a
 * page is busy and resume when it is ready. */
static void apply_raw(void *ctx) {
    (void)ctx;
    while (NRF_LOG_PROCESS());
    logflash_flush_blocking(100);
    bsp_wdt_feed();

    /* Own the flash controller outright: SoftDevice off, interrupts masked. */
    sd_softdevice_disable();
    __disable_irq();

    /* 1. Erase the whole bootloader region [0xF3000, 0xFE000); never the MBR
     *    param page at 0xFE000. */
    nvmc_mode(NVMC_CONFIG_WEN_Een);
    for (uint32_t a = BL_ADDR; a < BL_ADDR + BLSTAGE_MAX_LEN; a += PAGE_SIZE) {
        NRF_NVMC->ERASEPAGE = a;
        nvmc_settle();
        bsp_wdt_feed();
    }
    nvmc_mode(NVMC_CONFIG_WEN_Ren);

    /* 2. Write the staged image word by word from the staging area. */
    nvmc_mode(NVMC_CONFIG_WEN_Wen);
    const uint32_t *src = (const uint32_t *)BLSTAGE_BASE;
    volatile uint32_t *dst = (volatile uint32_t *)BL_ADDR;
    for (uint32_t i = 0; i < m_len / 4; i++) {
        dst[i] = src[i];
        nvmc_settle();
        if ((i & 0xFF) == 0) {
            bsp_wdt_feed();
        }
    }
    nvmc_mode(NVMC_CONFIG_WEN_Ren);

    /* 3. Register the bootloader with the MBR so it boots and future COPY_BL
     *    pushes work: NRFFW[0]=0xF3000, NRFFW[1]=MBR param page. UICR words are
     *    one-time-writable, so if either already points elsewhere the whole
     *    UICR must be erased first (wipes REGOUT0, restored in step 4). */
    uint32_t fw0 = NRF_UICR->NRFFW[0];
    uint32_t fw1 = NRF_UICR->NRFFW[1];
    if (fw0 != BL_ADDR || fw1 != MBR_PARAM_PAGE) {
        /* A UICR word can only be rewritten after a full UICR erase; erase only
         * when a word is non-blank and not already the value we want. */
        if ((fw0 != 0xFFFFFFFFu && fw0 != BL_ADDR) ||
                (fw1 != 0xFFFFFFFFu && fw1 != MBR_PARAM_PAGE)) {
            nvmc_mode(NVMC_CONFIG_WEN_Een);
            NRF_NVMC->ERASEUICR = 1;
            nvmc_settle();
            nvmc_mode(NVMC_CONFIG_WEN_Ren);
        }
        nvmc_mode(NVMC_CONFIG_WEN_Wen);
        if (NRF_UICR->NRFFW[0] != BL_ADDR) {
            NRF_UICR->NRFFW[0] = BL_ADDR;
            nvmc_settle();
        }
        if (NRF_UICR->NRFFW[1] != MBR_PARAM_PAGE) {
            NRF_UICR->NRFFW[1] = MBR_PARAM_PAGE;
            nvmc_settle();
        }
        nvmc_mode(NVMC_CONFIG_WEN_Ren);
    }

    /* 4. Restore REGOUT0 to 3.3V if it is at the erased default, so the board
     *    runs on battery (same rule as the app's REGOUT0 self-heal). */
    if ((NRF_UICR->REGOUT0 & UICR_REGOUT0_VOUT_Msk) ==
            (UICR_REGOUT0_VOUT_DEFAULT << UICR_REGOUT0_VOUT_Pos)) {
        nvmc_mode(NVMC_CONFIG_WEN_Wen);
        NRF_UICR->REGOUT0 = (NRF_UICR->REGOUT0 & ~(uint32_t)UICR_REGOUT0_VOUT_Msk) |
                            (UICR_REGOUT0_VOUT_3V3 << UICR_REGOUT0_VOUT_Pos);
        nvmc_settle();
        nvmc_mode(NVMC_CONFIG_WEN_Ren);
    }

    NVIC_SystemReset();
}

bls_err_t blstage_commit_raw(uint32_t magic) {
    if (magic != BLSTAGE_COMMIT_RAW_MAGIC) {
        return BLS_ERR_MAGIC;
    }
    bls_err_t e = verify_staged();
    if (e != BLS_OK) {
        return e;
    }
    /* ACL blocks NVMC too; fail now rather than fault mid-erase after reset. */
    if (bl_acl_write_locked(BL_ADDR, m_len)) {
        return BLS_ERR_ACL_LOCKED;
    }
    NRF_LOG_INFO("blstage: %u bytes staged, crc ok, RAW NVMC install + UICR convert in %d ms",
                 m_len, APPLY_DELAY_MS);
    return schedule_apply(apply_raw);
}
