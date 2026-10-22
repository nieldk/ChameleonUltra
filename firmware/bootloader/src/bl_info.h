/* Bootloader identity block at a fixed flash address, read by the app
 * (hw blver). Little-endian, 64 bytes, placed by bootloader-stage1.ld. */
#ifndef BL_INFO_H__
#define BL_INFO_H__

#include <stdint.h>

#define BL_INFO_ADDR    0x000FDFC0UL
#define BL_INFO_MAGIC   0x4E494C42UL   /* "BLIN" */
#define BL_INFO_LAYOUT  1

#define BL_FEAT_UF2      (1u << 0)
#define BL_FEAT_CDC_DFU  (1u << 1)
#define BL_FEAT_RAW_APP  (1u << 2)

typedef struct {
    uint32_t magic;
    uint16_t layout;
    uint16_t size;
    uint32_t version;      /* bootloader_version from build.sh */
    uint32_t features;     /* BL_FEAT_* */
    uint8_t  gcc[4];       /* major, minor, patch, 0 */
    char     rev[24];      /* "g1a2b3c[-dirty]", empty without git */
    uint8_t  reserved[20];
} bl_info_t;

_Static_assert(sizeof(bl_info_t) == 64, "bl_info_t must be 64 bytes");

#endif
