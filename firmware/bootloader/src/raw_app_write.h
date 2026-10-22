/* Unsigned in-place app write over the CDC serial DFU port (no Secure DFU).
 * Same flash path as UF2 drag-and-drop; CRC32 readback only. */
#ifndef RAW_APP_WRITE_H__
#define RAW_APP_WRITE_H__

#include <stdint.h>

#define RAW_APP_OP_BEGIN      0xD0  /* len(u32) + crc32(u32) */
#define RAW_APP_OP_WRITE      0xD1  /* offset(u32) + data */
#define RAW_APP_OP_COMMIT     0xD2  /* magic(u32) */
#define RAW_APP_COMMIT_MAGIC  0x52415721UL  /* "RAW!" */

typedef enum
{
    RAW_APP_OK = 0,
    RAW_APP_ERR_STATE,
    RAW_APP_ERR_LEN,
    RAW_APP_ERR_CRC,
    RAW_APP_ERR_MAGIC,
} raw_app_err_t;

raw_app_err_t raw_app_begin(uint32_t len, uint32_t crc32);
raw_app_err_t raw_app_write(uint32_t offset, uint8_t const * p_data, uint32_t len);
raw_app_err_t raw_app_commit(uint32_t magic);  /* resets on success */

#endif
