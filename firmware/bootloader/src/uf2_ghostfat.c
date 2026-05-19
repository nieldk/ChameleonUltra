/*
 * uf2_ghostfat.c — virtual FAT12 disk for ChameleonUltra UF2 bootloader.
 *
 * Synthesizes a small FAT12 volume containing two harmless files
 * (INFO_UF2.TXT, INDEX.HTM). The OS sees a normal removable drive and
 * happily lets the user drag a .uf2 onto it. We sniff each 512 B sector
 * write looking for UF2 frames; matching frames have their payload
 * forwarded to flash.
 *
 * Writes to FAT / root-dir / non-UF2 data sectors are silently ACKed
 * (no-op) — this keeps macOS and Windows happy while they decorate the
 * filesystem with .Trashes, $RECYCLE.BIN, System Volume Information, etc.
 *
 * MIT License. Original implementation.
 */
#include "uf2_ghostfat.h"
#include "uf2.h"
#include <string.h>

#define BPB_BYTES_PER_SECTOR    UF2_SECTOR_SIZE
#define BPB_SECTORS_PER_CLUSTER 1
#define BPB_RESERVED_SECTORS    1
#define BPB_NUM_FATS            2
#define BPB_ROOT_ENTRIES        64                 /* 64 * 32 = 2048 B = 4 sectors */
#define BPB_TOTAL_SECTORS       UF2_TOTAL_SECTORS  /* 8192 */
#define BPB_MEDIA_DESCRIPTOR    0xF8
#define BPB_SECTORS_PER_FAT     7    /* enough for 8192 12-bit entries: 12288 B / 512 ≈ 24… */
/* Actually we need to compute: each FAT entry is 12 bits, total_clusters ≈ 8186,
 * total bytes = 12288, sectors = 24. Use 24 to be safe. */
#undef  BPB_SECTORS_PER_FAT
#define BPB_SECTORS_PER_FAT     24

#define FAT_START_SECTOR        BPB_RESERVED_SECTORS                /* 1 */
#define ROOT_DIR_START_SECTOR   (FAT_START_SECTOR + BPB_NUM_FATS * BPB_SECTORS_PER_FAT) /* 1 + 48 = 49 */
#define ROOT_DIR_SECTORS        ((BPB_ROOT_ENTRIES * 32 + UF2_SECTOR_SIZE - 1) / UF2_SECTOR_SIZE) /* 4 */
#define DATA_START_SECTOR       (ROOT_DIR_START_SECTOR + ROOT_DIR_SECTORS) /* 53 */

/* Static files exposed on the virtual disk */
static const char INFO_TXT[] =
    "ChameleonUltra UF2 Bootloader\r\n"
    "Family: nRF52840 (0x1B57745F)\r\n"
    "App region: 0x27000-0xF3000\r\n"
    "Drop a .uf2 file here to flash.\r\n";

static const char INDEX_HTM[] =
    "<!doctype html><meta http-equiv=refresh content=\"0;url="
    "https://github.com/RfidResearchGroup/ChameleonUltra\">\r\n";

#define INFO_TXT_LEN  (sizeof(INFO_TXT) - 1)
#define INDEX_HTM_LEN (sizeof(INDEX_HTM) - 1)

#define INFO_TXT_CLUSTER   2
#define INDEX_HTM_CLUSTER  3

/* === State ============================================================== */
static uint32_t m_blocks_written;
static uint32_t m_num_blocks_expected;     /* learnt from first UF2 block */
static bool     m_completion_signalled;

/* === BPB and directory templates ======================================== */

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
    /* Extended BPB */
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_sig;
    uint32_t volume_id;
    uint8_t  volume_label[11];
    uint8_t  fs_type[8];
} fat_bpb_t;

typedef struct {
    uint8_t  name[11];        /* 8.3 padded with spaces */
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

_Static_assert(sizeof(fat_bpb_t) <= 90, "BPB too large");
_Static_assert(sizeof(fat_dir_entry_t) == 32, "dir entry must be 32B");

static const fat_bpb_t k_bpb = {
    .jump                = { 0xEB, 0x3C, 0x90 },
    .oem_name            = { 'M','S','D','O','S','5','.','0' },
    .bytes_per_sector    = BPB_BYTES_PER_SECTOR,
    .sectors_per_cluster = BPB_SECTORS_PER_CLUSTER,
    .reserved_sectors    = BPB_RESERVED_SECTORS,
    .num_fats            = BPB_NUM_FATS,
    .root_entries        = BPB_ROOT_ENTRIES,
    .total_sectors_16    = BPB_TOTAL_SECTORS,   /* fits in 16 bits */
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

/* Volume label directory entry (required by Windows to be at offset 0 of root). */
static const fat_dir_entry_t k_vol_label = {
    .name = { 'C','H','A','M','E','L','E','O','N',' ',' ' },
    .attr = 0x08, /* ATTR_VOLUME_ID */
};

static const fat_dir_entry_t k_info_txt = {
    .name = { 'I','N','F','O','_','U','F','2','T','X','T' },
    .attr = 0x01, /* ATTR_READ_ONLY */
    .first_cluster_lo = INFO_TXT_CLUSTER,
    .file_size = INFO_TXT_LEN,
};

static const fat_dir_entry_t k_index_htm = {
    .name = { 'I','N','D','E','X',' ',' ',' ','H','T','M' },
    .attr = 0x01,
    .first_cluster_lo = INDEX_HTM_CLUSTER,
    .file_size = INDEX_HTM_LEN,
};

/* === Helpers ============================================================ */

static void fat12_put(uint8_t *fat, uint32_t entry, uint16_t value)
{
    uint32_t off = entry + (entry >> 1);   /* entry * 1.5 */
    if (entry & 1) {
        fat[off]     = (fat[off] & 0x0F) | ((value & 0x0F) << 4);
        fat[off + 1] = (value >> 4) & 0xFF;
    } else {
        fat[off]     = value & 0xFF;
        fat[off + 1] = (fat[off + 1] & 0xF0) | ((value >> 8) & 0x0F);
    }
}

static void build_boot_sector(uint8_t *buf)
{
    memset(buf, 0, UF2_SECTOR_SIZE);
    memcpy(buf, &k_bpb, sizeof(k_bpb));
    buf[510] = 0x55;
    buf[511] = 0xAA;
}

static void build_fat_sector(uint32_t fat_sector_index, uint8_t *buf)
{
    memset(buf, 0, UF2_SECTOR_SIZE);
    if (fat_sector_index != 0) return;  /* rest of FAT is empty */

    /* Reserved entries + EOF chains for our two tiny files */
    fat12_put(buf, 0, 0xFF8);  /* media descriptor */
    fat12_put(buf, 1, 0xFFF);  /* EOC marker */
    fat12_put(buf, INFO_TXT_CLUSTER,  0xFFF);
    fat12_put(buf, INDEX_HTM_CLUSTER, 0xFFF);
}

static void build_root_dir_sector(uint32_t dir_sector_index, uint8_t *buf)
{
    memset(buf, 0, UF2_SECTOR_SIZE);
    if (dir_sector_index != 0) return;

    fat_dir_entry_t *e = (fat_dir_entry_t *)buf;
    e[0] = k_vol_label;
    e[1] = k_info_txt;
    e[2] = k_index_htm;
}

static void build_data_sector(uint32_t data_sector_index, uint8_t *buf)
{
    memset(buf, 0, UF2_SECTOR_SIZE);
    /* cluster N → data_sector_index = N - 2 (clusters start at 2) */
    if (data_sector_index == INFO_TXT_CLUSTER - 2) {
        memcpy(buf, INFO_TXT, INFO_TXT_LEN);
    } else if (data_sector_index == INDEX_HTM_CLUSTER - 2) {
        memcpy(buf, INDEX_HTM, INDEX_HTM_LEN);
    }
}

/* === Public API ========================================================= */

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
    if (lba >= BPB_TOTAL_SECTORS) {
        memset(buf, 0, UF2_SECTOR_SIZE);
        return 0;
    }

    if (lba == 0) {
        build_boot_sector(buf);
        return 0;
    }

    if (lba < ROOT_DIR_START_SECTOR) {
        /* FAT region — two identical copies of the FAT */
        uint32_t fat_idx = (lba - FAT_START_SECTOR) % BPB_SECTORS_PER_FAT;
        build_fat_sector(fat_idx, buf);
        return 0;
    }

    if (lba < DATA_START_SECTOR) {
        build_root_dir_sector(lba - ROOT_DIR_START_SECTOR, buf);
        return 0;
    }

    build_data_sector(lba - DATA_START_SECTOR, buf);
    return 0;
}

int uf2_ghostfat_write_block(uint32_t lba, const uint8_t *buf)
{
    /* We accept (and ignore) writes to system areas — boot/FAT/root —
     * which the OS will perform when it decorates the volume. */
    if (lba < DATA_START_SECTOR) {
        return 0;
    }

    if (!uf2_is_block(buf)) {
        return 0;   /* unknown content — silently drop */
    }

    const uf2_block_t *b = (const uf2_block_t *)buf;

    /* If the family ID flag is set, enforce nRF52840. */
    if ((b->flags & UF2_FLAG_FAMILYID) &&
        b->file_size_or_family_id != UF2_FAMILY_ID_NRF52840) {
        return 0;
    }

    /* Skip NO-FLASH blocks (used by some tools for comments). */
    if (b->flags & UF2_FLAG_NOFLASH) {
        return 0;
    }

    /* Bounds check the target address against the app region. */
    if (b->target_addr < UF2_FLASH_APP_START ||
        b->target_addr + b->payload_size > UF2_FLASH_APP_END) {
        return 0;   /* outside app window — refuse */
    }
    if (b->payload_size == 0 || b->payload_size > sizeof(b->data)) {
        return 0;
    }

    uf2_flash_write(b->target_addr, b->data, b->payload_size);

    /* Learn the expected total from the first valid block we see. */
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
