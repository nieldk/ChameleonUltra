/*
 * logring.h - flash layout and reader for the persistent debug log ring.
 *
 * Shared by the application (writer, utils/logflash.c) and the bootloader
 * (reader, exposed as LOG.TXT on the UF2 drive). Header-only, no SDK deps.
 *
 * Layout: LOGRING_PAGES pages of LOGRING_PAGE_SIZE bytes at LOGRING_BASE.
 * Each page: { magic, seq } header, then text. A page is filled completely
 * before the next one is opened, so only the newest page has an erased
 * (0xFF) tail. Oldest page = the one after the newest, cyclically.
 */
#ifndef LOGRING_H__
#define LOGRING_H__

#include <stdint.h>

#define LOGRING_BASE        0x000BF000UL   /* directly below the FDS area */
#define LOGRING_PAGE_SIZE   4096UL
#define LOGRING_PAGES       8UL
#define LOGRING_SIZE        (LOGRING_PAGE_SIZE * LOGRING_PAGES)
#define LOGRING_MAGIC       0x474F4C43UL   /* "CLOG" */
#define LOGRING_HDR_SIZE    8UL
#define LOGRING_PAGE_DATA   (LOGRING_PAGE_SIZE - LOGRING_HDR_SIZE)

typedef struct {
    uint32_t magic;
    uint32_t seq;
} logring_hdr_t;

typedef struct {
    uint32_t length;      /* total text bytes */
    uint32_t newest_seq;
    uint8_t  first;       /* physical index of oldest page */
    uint8_t  count;       /* valid pages, 0 = ring empty */
} logring_view_t;

static inline const logring_hdr_t *logring_hdr(uint32_t page) {
    return (const logring_hdr_t *)(LOGRING_BASE + page * LOGRING_PAGE_SIZE);
}

/* Fill *v from the flash contents. */
static inline void logring_scan(logring_view_t *v) {
    uint32_t newest = 0, cnt = 0;

    v->length = 0;
    v->newest_seq = 0;
    v->first = 0;
    for (uint32_t p = 0; p < LOGRING_PAGES; p++) {
        const logring_hdr_t *h = logring_hdr(p);
        if (h->magic != LOGRING_MAGIC) {
            continue;
        }
        if (cnt == 0 || (int32_t)(h->seq - v->newest_seq) > 0) {
            v->newest_seq = h->seq;
            newest = p;
        }
        cnt++;
    }
    v->count = (uint8_t)cnt;
    if (cnt == 0) {
        return;
    }
    v->first = (uint8_t)((newest + 1 + LOGRING_PAGES - cnt) % LOGRING_PAGES);

    /* newest page: used bytes = up to the first erased word */
    const uint32_t *w = (const uint32_t *)(LOGRING_BASE + newest * LOGRING_PAGE_SIZE + LOGRING_HDR_SIZE);
    uint32_t used = 0;
    while (used < LOGRING_PAGE_DATA && w[used / 4] != 0xFFFFFFFFUL) {
        used += 4;
    }
    v->length = (cnt - 1) * LOGRING_PAGE_DATA + used;
}

/* Copy up to len bytes of the logical log starting at off. Returns bytes copied. */
static inline uint32_t logring_read(const logring_view_t *v, uint32_t off, uint8_t *dst, uint32_t len) {
    uint32_t done = 0;

    while (done < len && off < v->length) {
        uint32_t page = (v->first + off / LOGRING_PAGE_DATA) % LOGRING_PAGES;
        uint32_t po   = off % LOGRING_PAGE_DATA;
        uint32_t n    = LOGRING_PAGE_DATA - po;
        if (n > len - done)      n = len - done;
        if (n > v->length - off) n = v->length - off;
        const uint8_t *src = (const uint8_t *)(LOGRING_BASE + page * LOGRING_PAGE_SIZE + LOGRING_HDR_SIZE + po);
        for (uint32_t i = 0; i < n; i++) {
            dst[done + i] = src[i];
        }
        done += n;
        off  += n;
    }
    return done;
}

#endif /* LOGRING_H__ */
