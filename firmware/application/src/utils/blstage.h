#ifndef BLSTAGE_H
#define BLSTAGE_H

#include <stdint.h>

/* Staging area for a new bootloader image, directly below the log ring. */
#define BLSTAGE_BASE        0x000B0000UL
#define BLSTAGE_AREA        0x0000F000UL   /* up to 0xBF000 */
#define BLSTAGE_MAX_LEN     0x0000B000UL   /* bootloader region size */
#define BLSTAGE_CHUNK_MAX   256u
#define BLSTAGE_COMMIT_MAGIC 0x434F5059UL  /* "COPY" */
#define BLSTAGE_COMMIT_RAW_MAGIC 0x52415721UL  /* "RAW!" */

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
    BLS_ERR_ACL_LOCKED, /* 0xF3000 is ACL write-locked; no app-side write possible */
} bls_err_t;

bls_err_t blstage_begin(uint32_t len, uint32_t crc32);
bls_err_t blstage_write(uint32_t offset, const uint8_t *data, uint32_t len);
bls_err_t blstage_commit(uint32_t magic);

/* Like blstage_commit, but installs the staged image WITHOUT the MBR: after the
 * SoftDevice is disabled it erases/writes 0xF3000 through NVMC directly, then
 * registers the bootloader with the MBR (UICR NRFFW[0]=0xF3000, NRFFW[1]=MBR
 * param page, erasing UICR first if either already points elsewhere) and
 * restores REGOUT0 to 3.3V. For devices whose bootloader was never MBR-
 * registered, where COPY_BL is unavailable. No journaling: a power loss mid-
 * write bricks the device (SWD-only recovery). */
bls_err_t blstage_commit_raw(uint32_t magic);

#endif
