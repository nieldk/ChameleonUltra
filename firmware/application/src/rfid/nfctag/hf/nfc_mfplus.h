#ifndef NFC_MFPLUS_H
#define NFC_MFPLUS_H

#include "nfc_14a.h"
#include "tag_emulation.h"

// v1 scope: card starts already provisioned in SL3 (no SL0 personalization
// protocol, no AuthenticateNonFirst). All sectors share one configurable
// 16-byte AES key for both Key A and Key B slots -- real MIFARE Plus has an
// independent key per sector/keytype; this is a deliberate simplification.
// Protocol (AuthenticateFirst, ReadBlock, WriteBlock, GetVersion byte
// layout, session-key derivation, CMAC and data-IV construction) verified
// against RRG proxmark3's client/src/mifare/mifare4.c and cmdhfmfp.c
// (mfp_data_crypt), both GPLv3, and cross-checked with a standalone
// Python round-trip of the full handshake + a MACed/encrypted ReadBlock
// before this was written.

#define NFC_TAG_MFPLUS_KEY_SIZE   16
#define NFC_TAG_MFPLUS_BLOCK_SIZE 16
#define NFC_TAG_MFPLUS_BLOCK_MAX  256   // matches NFC_TAG_MF1_BLOCK_MAX

typedef struct __attribute__((packed)) {
    nfc_tag_14a_coll_res_entity_t res_coll;
    uint8_t  block_max;    // 128 (2K) or 256 (4K), set at factory time
    uint8_t  default_key[NFC_TAG_MFPLUS_KEY_SIZE];  // shared Key A/B, all sectors
    uint8_t  memory[NFC_TAG_MFPLUS_BLOCK_MAX][NFC_TAG_MFPLUS_BLOCK_SIZE];
}
nfc_tag_mfplus_information_t;

nfc_tag_14a_coll_res_reference_t *nfc_tag_mfplus_get_coll_res(void);

int  nfc_tag_mfplus_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer);
int  nfc_tag_mfplus_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer);
bool nfc_tag_mfplus_data_factory(uint8_t slot, tag_specific_type_t tag_type);

#endif
