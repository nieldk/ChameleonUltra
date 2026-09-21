#pragma once

#ifndef INDALA_H_
#define INDALA_H_

#include "protocols.h"

extern const protocol indala;

uint8_t indala_t55xx_writer(uint8_t* uid, uint32_t* blks);
void indala_get_debug(uint8_t *off, uint16_t *nb, int32_t *mag);

#endif /* INDALA_H_ */
