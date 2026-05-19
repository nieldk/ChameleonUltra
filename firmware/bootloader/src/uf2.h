/*
 * UF2 block format definitions.
 * Spec: https://github.com/microsoft/uf2
 *
 * MIT License. Self-contained reimplementation of the public UF2 wire format.
 */
#ifndef UF2_H__
#define UF2_H__

#include <stdint.h>
#include <stdbool.h>

#define UF2_MAGIC_START0    0x0A324655UL /* "UF2\n" */
#define UF2_MAGIC_START1    0x9E5D5157UL /* random */
#define UF2_MAGIC_END       0x0AB16F30UL /* random */

/* Family ID for nRF52840, registered upstream in microsoft/uf2. */
#define UF2_FAMILY_ID_NRF52840   0x1B57745FUL

/* Flag bits in uf2_block_t.flags */
#define UF2_FLAG_NOFLASH        0x00000001UL
#define UF2_FLAG_FAMILYID       0x00002000UL
#define UF2_FLAG_MD5CHECKSUM    0x00004000UL
#define UF2_FLAG_EXTENSION_TAGS 0x00008000UL

typedef struct __attribute__((packed)) {
    /* 32-byte header */
    uint32_t magic_start0;
    uint32_t magic_start1;
    uint32_t flags;
    uint32_t target_addr;
    uint32_t payload_size;
    uint32_t block_no;
    uint32_t num_blocks;
    uint32_t file_size_or_family_id;
    /* 476-byte data area */
    uint8_t  data[476];
    /* trailing magic */
    uint32_t magic_end;
} uf2_block_t;

_Static_assert(sizeof(uf2_block_t) == 512, "uf2_block_t must be 512 bytes");

static inline bool uf2_is_block(const void *p)
{
    const uf2_block_t *b = (const uf2_block_t *)p;
    return b->magic_start0 == UF2_MAGIC_START0 &&
           b->magic_start1 == UF2_MAGIC_START1 &&
           b->magic_end    == UF2_MAGIC_END;
}

#endif /* UF2_H__ */
