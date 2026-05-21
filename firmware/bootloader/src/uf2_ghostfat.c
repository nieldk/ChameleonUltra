/*
 * uf2_ghostfat.c — virtual FAT12 disk for ChameleonUltra UF2 bootloader.
 *
 * Now with status reporting: INFO_UF2.TXT is always present in the root,
 * and after each UF2 transfer attempt either RESULT.TXT or FAIL.TXT
 * surfaces what happened. Helps when transfers silently drop blocks or
 * the host's MSC layer reports success despite actual flash rejections.
 *
 * MIT License.
 */
#include "uf2_ghostfat.h"
#include "uf2.h"
#include "uf2_status.h"
#include <string.h>

#define BPB_BYTES_PER_SECTOR    UF2_SECTOR_SIZE
#define BPB_SECTORS_PER_CLUSTER 1
#define BPB_RESERVED_SECTORS    1
#define BPB_NUM_FATS            2
#define BPB_ROOT_ENTRIES        16     /* 16 * 32 = 512 B = 1 sector — minimal */
#define BPB_TOTAL_SECTORS       UF2_TOTAL_SECTORS
#define BPB_MEDIA_DESCRIPTOR    0xF8
#define BPB_SECTORS_PER_FAT     24     /* enough for FAT12 with this many clusters */

#define FAT_START_SECTOR        BPB_RESERVED_SECTORS
#define ROOT_DIR_START_SECTOR   (FAT_START_SECTOR + BPB_NUM_FATS * BPB_SECTORS_PER_FAT)
#define ROOT_DIR_SECTORS        ((BPB_ROOT_ENTRIES * 32 + UF2_SECTOR_SIZE - 1) / UF2_SECTOR_SIZE)
#define DATA_START_SECTOR       (ROOT_DIR_START_SECTOR + ROOT_DIR_SECTORS)

/* Status files occupy the first two data clusters. With 1 sector per
 * cluster, cluster 2 maps to DATA_START_SECTOR and cluster 3 to
 * DATA_START_SECTOR + 1. */
#define INFO_FILE_CLUSTER       2
#define STATUS_FILE_CLUSTER     3      /* RESULT.TXT or FAIL.TXT */

#define INFO_FILE_SECTOR        DATA_START_SECTOR
#define STATUS_FILE_SECTOR      (DATA_START_SECTOR + 1)

static uint32_t m_blocks_written;
static uint32_t m_num_blocks_expected;
static bool     m_completion_signalled;

#pragma pack(push, 1)
typedef struct {
    uint8_t  jump[3];
    uint8_t  oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  num_fats;
    uint16_t root_entries;
    uint16_t total_sectors_16;
    uint8_t  media_descriptor;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_sig;
    uint32_t volume_id;
    uint8_t  volume_label[11];
    uint8_t  fs_type[8];
} fat_bpb_t;

typedef struct {
    uint8_t  name[11];
    uint8_t  attr;
    uint8_t  ntres;
    uint8_t  ctime_tenth;
    uint16_t ctime;
    uint16_t cdate;
    uint16_t adate;
    uint16_t first_cluster_hi;
    uint16_t wtime;
    uint16_t wdate;
    uint16_t first_cluster_lo;
    uint32_t file_size;
} fat_dir_entry_t;
#pragma pack(pop)

_Static_assert(sizeof(fat_dir_entry_t) == 32, "dir entry must be 32B");

static const fat_bpb_t k_bpb = {
    .jump                = { 0xEB, 0x3C, 0x90 },
    .oem_name            = { 'M','S','D','O','S','5','.','0' },
    .bytes_per_sector    = BPB_BYTES_PER_SECTOR,
    .sectors_per_cluster = BPB_SECTORS_PER_CLUSTER,
    .reserved_sectors    = BPB_RESERVED_SECTORS,
    .num_fats            = BPB_NUM_FATS,
    .root_entries        = BPB_ROOT_ENTRIES,
    .total_sectors_16    = BPB_TOTAL_SECTORS,
    .media_descriptor    = BPB_MEDIA_DESCRIPTOR,
    .sectors_per_fat     = BPB_SECTORS_PER_FAT,
    .sectors_per_track   = 1,
    .num_heads           = 1,
    .hidden_sectors      = 0,
    .total_sectors_32    = 0,
    .drive_number        = 0x80,
    .reserved1           = 0,
    .boot_sig            = 0x29,
    .volume_id           = 0x00420042,
    .volume_label        = { 'C','H','A','M','E','L','E','O','N',' ',' ' },
    .fs_type             = { 'F','A','T','1','2',' ',' ',' ' },
};

static const fat_dir_entry_t k_vol_label = {
    .name = { 'C','H','A','M','E','L','E','O','N',' ',' ' },
    .attr = 0x08,
};

static void fat12_put(uint8_t *fat, uint32_t entry, uint16_t value)
{
    uint32_t off = entry + (entry >> 1);
    if (entry & 1) {
        fat[off]     = (fat[off] & 0x0F) | ((value & 0x0F) << 4);
        fat[off + 1] = (value >> 4) & 0xFF;
    } else {
        fat[off]     = value & 0xFF;
        fat[off + 1] = (fat[off + 1] & 0xF0) | ((value >> 8) & 0x0F);
    }
}

/* Fill in a directory entry for a regular file at `cluster` with `size`
 * bytes. The 11-char name is the 8.3 short form, padded with spaces
 * (e.g., "INFO_UF2TXT" for "INFO_UF2.TXT"). */
static void dir_make_file(fat_dir_entry_t *e, const char *name11,
                          uint16_t cluster, uint32_t size)
{
    memset(e, 0, sizeof(*e));
    memcpy(e->name, name11, 11);
    e->attr             = 0x20;     /* archive */
    e->cdate            = 0x5221;   /* 2021-01-01 — any valid date */
    e->adate            = 0x5221;
    e->wdate            = 0x5221;
    e->first_cluster_lo = cluster;
    e->file_size        = size;
}

void uf2_ghostfat_init(void)
{
    m_blocks_written = 0;
    m_num_blocks_expected = 0;
    m_completion_signalled = false;
    uf2_status_init();
}

uint32_t uf2_ghostfat_blocks_written(void) { return m_blocks_written; }
bool     uf2_ghostfat_is_complete(void)    { return m_completion_signalled; }

int uf2_ghostfat_read_block(uint32_t lba, uint8_t *buf)
{
    memset(buf, 0, UF2_SECTOR_SIZE);

    if (lba >= BPB_TOTAL_SECTORS) {
        return 0;
    }

    if (lba == 0) {
        memcpy(buf, &k_bpb, sizeof(k_bpb));
        buf[510] = 0x55;
        buf[511] = 0xAA;
        return 0;
    }

    if (lba < ROOT_DIR_START_SECTOR) {
        /* FAT region — first sector of each FAT copy has the reserved
         * entries plus end-of-chain markers for the status files. */
        uint32_t fat_idx = (lba - FAT_START_SECTOR) % BPB_SECTORS_PER_FAT;
        if (fat_idx == 0) {
            fat12_put(buf, 0, 0xFF8);
            fat12_put(buf, 1, 0xFFF);
            /* cluster 2 (INFO_UF2.TXT) — single-cluster file */
            fat12_put(buf, INFO_FILE_CLUSTER, 0xFFF);
            /* cluster 3 (RESULT.TXT or FAIL.TXT) — single-cluster file,
             * always marked end-of-chain even when no status file is
             * currently visible. Cheaper than conditional and harmless;
             * the cluster only gets read if it's referenced by a dir
             * entry, which it isn't until a transfer happens. */
            fat12_put(buf, STATUS_FILE_CLUSTER, 0xFFF);
        }
        return 0;
    }

    if (lba == ROOT_DIR_START_SECTOR) {
        fat_dir_entry_t *entries = (fat_dir_entry_t *)buf;

        /* Slot 0: volume label */
        memcpy(&entries[0], &k_vol_label, sizeof(k_vol_label));

        /* Slot 1: INFO_UF2.TXT — always present */
        {
            uint32_t info_sz;
            (void)uf2_status_get_info_txt(&info_sz);
            dir_make_file(&entries[1], "INFO_UF2TXT",
                          INFO_FILE_CLUSTER, info_sz);
        }

        /* Slot 2: RESULT.TXT or FAIL.TXT — only one, depending on
         * the outcome of the most recent transfer attempt (if any) */
        if (uf2_status_has_result()) {
            uint32_t sz;
            (void)uf2_status_get_result_txt(&sz);
            dir_make_file(&entries[2], "RESULT  TXT",
                          STATUS_FILE_CLUSTER, sz);
        } else if (uf2_status_has_failure()) {
            uint32_t sz;
            (void)uf2_status_get_fail_txt(&sz);
            dir_make_file(&entries[2], "FAIL    TXT",
                          STATUS_FILE_CLUSTER, sz);
        }
        /* If neither: slot 2 stays zeroed, which terminates the
         * directory listing per FAT spec. */

        return 0;
    }

    /* Data area: serve status file contents from clusters 2 and 3. */
    if (lba == INFO_FILE_SECTOR) {
        uint32_t sz;
        const char *txt = uf2_status_get_info_txt(&sz);
        if (sz > UF2_SECTOR_SIZE) sz = UF2_SECTOR_SIZE;
        memcpy(buf, txt, sz);
        return 0;
    }
    if (lba == STATUS_FILE_SECTOR) {
        const char *txt = NULL;
        uint32_t sz = 0;
        if (uf2_status_has_result()) {
            txt = uf2_status_get_result_txt(&sz);
        } else if (uf2_status_has_failure()) {
            txt = uf2_status_get_fail_txt(&sz);
        }
        if (txt && sz > 0) {
            if (sz > UF2_SECTOR_SIZE) sz = UF2_SECTOR_SIZE;
            memcpy(buf, txt, sz);
        }
        return 0;
    }

    /* Everything else (rest of root dir, all data sectors) reads as zeros. */
    return 0;
}

int uf2_ghostfat_write_block(uint32_t lba, const uint8_t *buf)
{
    /* Swallow writes to system area (boot/FAT/root). */
    if (lba < DATA_START_SECTOR) {
        return 0;
    }

    if (!uf2_is_block(buf)) {
        /* Not a UF2 block at all — could be filesystem metadata the
         * host is trying to write (FAT update, etc). Silently ignored,
         * but don't count it as a rejected UF2 since it never claimed
         * to be one. */
        return 0;
    }

    const uf2_block_t *b = (const uf2_block_t *)buf;

    if ((b->flags & UF2_FLAG_FAMILYID) &&
        b->file_size_or_family_id != UF2_FAMILY_ID_NRF52840) {
        uf2_status_record_rejected(b->block_no, b->num_blocks,
                                   b->target_addr, UF2_REJECT_FAMILY);
        return 0;
    }
    if (b->flags & UF2_FLAG_NOFLASH) {
        /* No-flash blocks are valid UF2 but explicitly opt out of
         * flashing. Don't count them as accepted or rejected. */
        return 0;
    }
    if (b->target_addr < UF2_FLASH_APP_START ||
        b->target_addr + b->payload_size > UF2_FLASH_APP_END) {
        uf2_status_record_rejected(b->block_no, b->num_blocks,
                                   b->target_addr, UF2_REJECT_BOUNDS);
        return 0;
    }
    if (b->payload_size == 0 || b->payload_size > sizeof(b->data)) {
        uf2_status_record_rejected(b->block_no, b->num_blocks,
                                   b->target_addr, UF2_REJECT_SEQ);
        return 0;
    }
    if (b->num_blocks != 0 && b->block_no >= b->num_blocks) {
        uf2_status_record_rejected(b->block_no, b->num_blocks,
                                   b->target_addr, UF2_REJECT_SEQ);
        return 0;
    }

    uf2_flash_write(b->target_addr, b->data, b->payload_size);

    uf2_status_record_accepted(b->block_no, b->num_blocks, b->target_addr);

    if (m_num_blocks_expected == 0 && b->num_blocks != 0) {
        m_num_blocks_expected = b->num_blocks;
    }
    m_blocks_written++;

    if (!m_completion_signalled &&
        m_num_blocks_expected != 0 &&
        m_blocks_written >= m_num_blocks_expected) {
        m_completion_signalled = true;
        uf2_status_record_complete();
        uf2_dfu_complete();
    }
    return 0;
}
