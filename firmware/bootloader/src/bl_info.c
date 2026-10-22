#include "bl_info.h"

#ifndef BL_VERSION
#define BL_VERSION 0
#endif
#ifndef BL_GIT_REV
#define BL_GIT_REV ""
#endif

const bl_info_t g_bl_info __attribute__((used, section(".bl_info"))) = {
    .magic    = BL_INFO_MAGIC,
    .layout   = BL_INFO_LAYOUT,
    .size     = sizeof(bl_info_t),
    .version  = BL_VERSION,
    .features = BL_FEAT_UF2 | BL_FEAT_CDC_DFU | BL_FEAT_RAW_APP,
    .gcc      = { __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__, 0 },
    .rev      = BL_GIT_REV,
};
