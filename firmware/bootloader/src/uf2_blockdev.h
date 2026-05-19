/*
 * uf2_blockdev.h — exposes ghostfat as an nrf_block_dev_t
 * so it can plug into Nordic SDK's APP_USBD_MSC_GLOBAL_DEF.
 */
#ifndef UF2_BLOCKDEV_H__
#define UF2_BLOCKDEV_H__

#include "nrf_block_dev.h"

extern const nrf_block_dev_t uf2_blockdev;

#endif
