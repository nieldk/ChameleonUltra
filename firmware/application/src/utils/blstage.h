#ifndef BLSTAGE_H
#define BLSTAGE_H

#include <stdint.h>

/* Staging area for a new bootloader image, directly below the log ring. */
#define BLSTAGE_BASE        0x000B0000UL
#define BLSTAGE_AREA        0x0000F000UL   /* up to 0xBF000 */
#define BLSTAGE_MAX_LEN     0x0000B000UL   /* bootloader region size */
#define BLSTAGE_CHUNK_MAX   256u
#define BLSTAGE_COMMIT_MAGIC 0x434F5059UL  /* "COPY" */

/* Reason byte returned with a failed command. */
typedef enum {
    BLS_OK = 0,
    BLS_ERR_LEN,        /* bad length or offset */
    BLS_ERR_NO_PARAM,   /* MBR param page not configured (UICR) */
    BLS_ERR_NO_BLADDR,  /* bootloader address not 0xF3000 */
    BLS_ERR_FLASH,      /* flash erase/write failed */
    BLS_ERR_STATE,      /* wrong order of commands */
    BLS_ERR_CRC,
    BLS_ERR_IMAGE,      /* vector table does not look like the bootloader */
    BLS_ERR_MAGIC,
} bls_err_t;

bls_err_t blstage_begin(uint32_t len, uint32_t crc32);
bls_err_t blstage_write(uint32_t offset, const uint8_t *data, uint32_t len);
bls_err_t blstage_commit(uint32_t magic);

#endif
