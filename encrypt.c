#include "encrypt.h"


void encrypt_xor(uint8_t *buf, size_t size, uint8_t key) {
    for(size_t i = 0; i < size; i++) {
        buf[i] ^= key;
    }
}

