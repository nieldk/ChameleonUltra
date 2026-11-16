#pragma once

#include <stdint.h>

#include "lf_ia.h"

// The slot data of a Hitag 2 tag: its eight 32-bit pages, page 0 first, each most significant byte first. Page 0 is
// the UID, page 1 the reader password, page 3 the configuration byte and the tag password.
#define LF_HITAG2_PAGES     (8u)
#define LF_HITAG2_DATA_SIZE (4u * LF_HITAG2_PAGES)

// Sets the pages the module answers from and returns the module, for lf_ia_set_module.
const lf_ia_module_t *lf_ia_hitag2_load(const uint8_t *pages);
