/*
 * uf2_ghostfat.c — virtual FAT12 disk for ChameleonUltra UF2 bootloader.
 *
 * Slim variant: no INFO_UF2.TXT or INDEX.HTM files. The volume mounts as
 * an empty FAT12 disk labelled "CHAMELEON". The user drops a .uf2 file
 * onto it and it gets flashed; reads of the data area return zeros.
 *
 * MIT License.
 */
#include "uf2_ghostfat.h"
#include "uf2.h"
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

void uf2_ghostfat_init(void)
{
    m_blocks_written = 0;
    m_num_blocks_expected = 0;
    m_completion_signalled = false;
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
        /* FAT region — only first sector of each FAT copy has the
         * reserved entries; the rest of each FAT is empty. */
        uint32_t fat_idx = (lba - FAT_START_SECTOR) % BPB_SECTORS_PER_FAT;
        if (fat_idx == 0) {
            fat12_put(buf, 0, 0xFF8);
            fat12_put(buf, 1, 0xFFF);
        }
        return 0;
    }

    if (lba == ROOT_DIR_START_SECTOR) {
        memcpy(buf, &k_vol_label, sizeof(k_vol_label));
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
        return 0;
    }

    const uf2_block_t *b = (const uf2_block_t *)buf;

    if ((b->flags & UF2_FLAG_FAMILYID) &&
        b->file_size_or_family_id != UF2_FAMILY_ID_NRF52840) {
        return 0;
    }
    if (b->flags & UF2_FLAG_NOFLASH) {
        return 0;
    }
    if (b->target_addr < UF2_FLASH_APP_START ||
        b->target_addr + b->payload_size > UF2_FLASH_APP_END) {
        return 0;
    }
    if (b->payload_size == 0 || b->payload_size > sizeof(b->data)) {
        return 0;
    }

    uf2_flash_write(b->target_addr, b->data, b->payload_size);

    if (m_num_blocks_expected == 0 && b->num_blocks != 0) {
        m_num_blocks_expected = b->num_blocks;
    }
    m_blocks_written++;

    if (!m_completion_signalled &&
        m_num_blocks_expected != 0 &&
        m_blocks_written >= m_num_blocks_expected) {
        m_completion_signalled = true;
        uf2_dfu_complete();
    }
    return 0;
}
