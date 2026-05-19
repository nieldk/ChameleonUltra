/*
 * uf2_blockdev.c — nrf_block_dev_t whose backing store is ghostfat.
 *
 * The Nordic MSC class doesn't take direct read/write callbacks; it
 * takes a list of nrf_block_dev_t instances. We implement the ops
 * vtable here, delegating to the ghostfat layer.
 *
 * MIT License.
 */
#include "uf2_blockdev.h"
#include "uf2_ghostfat.h"
#include "sdk_errors.h"
#include <string.h>

static nrf_block_dev_ev_handler m_ev_handler;
static void const *             m_ev_context;

static const nrf_block_dev_geometry_t m_geometry = {
    .blk_count = UF2_TOTAL_SECTORS,
    .blk_size  = UF2_SECTOR_SIZE,
};

static const nrf_block_dev_info_strings_t m_info_strings = {
    .p_vendor   = "RRG",
    .p_product  = "ChameleonUltra",
    .p_revision = "1.0 ",
};

static void fire_event(nrf_block_dev_t const *p_blk_dev,
                       nrf_block_dev_event_type_t type,
                       nrf_block_req_t const *p_req)
{
    if (!m_ev_handler) return;
    nrf_block_dev_event_t ev = {
        .ev_type   = type,
        .result    = NRF_BLOCK_DEV_RESULT_SUCCESS,
        .p_blk_req = p_req,
        .p_context = m_ev_context,
    };
    m_ev_handler(p_blk_dev, &ev);
}

static ret_code_t op_init(nrf_block_dev_t const *p_blk_dev,
                          nrf_block_dev_ev_handler ev_handler,
                          void const *p_context)
{
    m_ev_handler = ev_handler;
    m_ev_context = p_context;
    uf2_ghostfat_init();
    fire_event(p_blk_dev, NRF_BLOCK_DEV_EVT_INIT, NULL);
    return NRF_SUCCESS;
}

static ret_code_t op_uninit(nrf_block_dev_t const *p_blk_dev)
{
    fire_event(p_blk_dev, NRF_BLOCK_DEV_EVT_UNINIT, NULL);
    m_ev_handler = NULL;
    return NRF_SUCCESS;
}

static ret_code_t op_read(nrf_block_dev_t const *p_blk_dev,
                          nrf_block_req_t const *p_req)
{
    uint8_t *out = (uint8_t *)p_req->p_buff;
    for (uint32_t i = 0; i < p_req->blk_count; ++i) {
        uf2_ghostfat_read_block(p_req->blk_id + i, out + i * UF2_SECTOR_SIZE);
    }
    fire_event(p_blk_dev, NRF_BLOCK_DEV_EVT_BLK_READ_DONE, p_req);
    return NRF_SUCCESS;
}

static ret_code_t op_write(nrf_block_dev_t const *p_blk_dev,
                           nrf_block_req_t const *p_req)
{
    const uint8_t *in = (const uint8_t *)p_req->p_buff;
    for (uint32_t i = 0; i < p_req->blk_count; ++i) {
        uf2_ghostfat_write_block(p_req->blk_id + i, in + i * UF2_SECTOR_SIZE);
    }
    fire_event(p_blk_dev, NRF_BLOCK_DEV_EVT_BLK_WRITE_DONE, p_req);
    return NRF_SUCCESS;
}

static ret_code_t op_ioctl(nrf_block_dev_t const *p_blk_dev,
                           nrf_block_dev_ioctl_req_t req,
                           void *p_data)
{
    (void)p_blk_dev;
    switch (req) {
        case NRF_BLOCK_DEV_IOCTL_REQ_CACHE_FLUSH:
            if (p_data) *(bool *)p_data = true;
            return NRF_SUCCESS;
        case NRF_BLOCK_DEV_IOCTL_REQ_INFO_STRINGS:
            if (p_data) {
                *(const nrf_block_dev_info_strings_t **)p_data = &m_info_strings;
            }
            return NRF_SUCCESS;
        default:
            return NRF_ERROR_NOT_SUPPORTED;
    }
}

static nrf_block_dev_geometry_t const *op_geometry(nrf_block_dev_t const *p_blk_dev)
{
    (void)p_blk_dev;
    return &m_geometry;
}

static const struct nrf_block_dev_ops_s m_ops = {
    .init     = op_init,
    .uninit   = op_uninit,
    .read_req = op_read,
    .write_req= op_write,
    .ioctl    = op_ioctl,
    .geometry = op_geometry,
};

const nrf_block_dev_t uf2_blockdev = {
    .p_ops = &m_ops,
};
