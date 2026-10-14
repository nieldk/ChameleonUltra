#ifndef FDS_UTIL_H__
#define FDS_UTIL_H__

#include "fds.h"


bool fds_read_sync(uint16_t id, uint16_t key, uint16_t *length, uint8_t *buffer);
bool fds_write_sync(uint16_t id, uint16_t key, uint16_t length, void *buffer);
int fds_delete_sync(uint16_t id, uint16_t key);
bool fds_is_exists(uint16_t id, uint16_t key);
void fds_util_init(void);
void fds_gc_sync(void);
bool fds_wipe(void);

/* One record's metadata, for enumeration (hw fds). */
typedef struct {
    uint16_t file_id;
    uint16_t key;
    uint16_t len_bytes;
} fds_rec_meta_t;

/* Walk all valid FDS records, filling up to max entries. Returns the count. */
int fds_enumerate(fds_rec_meta_t *out, int max);

/* Zero-copy read: return a flash pointer to the record data and its byte
   length, or NULL if absent. Call fds_peek_close() with the same desc once the
   data has been consumed (no RAM copy, so large records cost nothing). */
const uint8_t *fds_peek(uint16_t id, uint16_t key, uint16_t *len_bytes, fds_record_desc_t *desc);
void fds_peek_close(fds_record_desc_t *desc);

#endif
