#ifndef NFC_MFPLUS_H
#define NFC_MFPLUS_H

#include "nfc_14a.h"
#include "tag_emulation.h"

// v2 scope: real SL0 personalization (WritePerso/CommitPerso), per-sector
// AES keys (Key A/B), AuthenticateFirst and AuthenticateNonFirst, CMAC'd
// and AES-CBC encrypted ReadBlock/WriteBlock, GetVersion. SL0 can only
// reach SL3 directly (no SL1 path) -- matches the real card's SL0->SL1 or
// SL0->SL3 choice, minus the SL1/backwards-compatible leg.
//
// Admin/system keys other than CardMasterKey (0x9000), CardConfigKey
// (0x9001) and L3SwitchKey (0x9003) -- and the B0/A0/C0 config and virtual
// -card blocks -- are accepted during WritePerso (ack'd, so a real `hf mfp
// initp` run completes) but not stored or semantically enforced: their
// exact behaviour is in NXP's confidential MIFARE Plus functional spec,
// not the public datasheet, and nothing in RRG proxmark3 depends on it
// either.
//
// Protocol (AuthenticateFirst/NonFirst, ReadBlock, WriteBlock, GetVersion,
// WritePerso/CommitPerso byte layout, session-key derivation, CMAC and
// data-IV construction) matches RRG proxmark3's client/src/mifare/mifare4.c
// and cmdhfmfp.c (mfp_data_crypt), both GPLv3, including proxmark3's own
// documented caveat that the AuthenticateNonFirst IV construction is not
// confirmed against the confidential datasheet (see mifare4.c's comment
// above its nonfirst branch) -- this firmware mirrors that exact
// construction so it round-trips against proxmark3 as a reader.

#define NFC_TAG_MFPLUS_KEY_SIZE     16
#define NFC_TAG_MFPLUS_BLOCK_SIZE   16
#define NFC_TAG_MFPLUS_BLOCK_MAX    256   // matches NFC_TAG_MF1_BLOCK_MAX
#define NFC_TAG_MFPLUS_MAX_SECTORS  40    // S4K sector count (32*4blk + 8*16blk)

#define MFPLUS_LEVEL_SL0  0
#define MFPLUS_LEVEL_SL3  3

typedef struct __attribute__((packed)) {
    nfc_tag_14a_coll_res_entity_t res_coll;
    uint16_t block_max;     // 128 (2K) or 256 (4K), set at factory time -- must be
                            // wide enough to hold 256 (a uint8_t here silently
                            // wraps 256 to 0 and bricks every S4K check)
    uint8_t  num_sectors;   // 32 (2K) or 40 (4K)
    uint8_t  level;         // MFPLUS_LEVEL_SL0 / MFPLUS_LEVEL_SL3
    uint8_t  master_key_written;     // 0x9000 written this personalization
    uint8_t  config_key_written;     // 0x9001 written this personalization
    uint8_t  l3_switch_key_written;  // 0x9003 written this personalization
    uint8_t  master_key[NFC_TAG_MFPLUS_KEY_SIZE];
    uint8_t  config_key[NFC_TAG_MFPLUS_KEY_SIZE];
    uint8_t  l3_switch_key[NFC_TAG_MFPLUS_KEY_SIZE];
    uint8_t  sector_keys[NFC_TAG_MFPLUS_MAX_SECTORS][2][NFC_TAG_MFPLUS_KEY_SIZE]; // [sector][A=0/B=1]
    uint8_t  memory[NFC_TAG_MFPLUS_BLOCK_MAX][NFC_TAG_MFPLUS_BLOCK_SIZE];
}
nfc_tag_mfplus_information_t;

nfc_tag_14a_coll_res_reference_t *nfc_tag_mfplus_get_coll_res(void);

int  nfc_tag_mfplus_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer);
int  nfc_tag_mfplus_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer);
bool nfc_tag_mfplus_data_factory(uint8_t slot, tag_specific_type_t tag_type);

// Management API for app_cmd.c -- same WritePerso/CommitPerso semantics the
// wire commands (0xA8/0xAA) use, minus the APDU framing. Returns a MIFARE
// Plus status byte (0x90 = OK); see nfc_mfplus.c's STATUS_* for the rest.
// Write is gated to SL0 by the caller (check nfc_tag_mfplus_get_status first).
uint8_t nfc_tag_mfplus_write_perso(uint8_t addr_hi, uint8_t addr_lo, const uint8_t *key);
uint8_t nfc_tag_mfplus_commit_perso(void);
void    nfc_tag_mfplus_get_status(uint8_t *level, uint16_t *block_max);

#endif
