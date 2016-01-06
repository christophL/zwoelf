#pragma once
#include <stdlib.h>
#include <stdint.h>

void encrypt_xor(uint8_t *start, size_t size, uint8_t key);