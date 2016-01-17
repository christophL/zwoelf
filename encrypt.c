#include "encrypt.h"


void encrypt_xor(uint8_t* buf, size_t size, uint8_t key) {
    for(size_t i = 0; i < size; i++) {
        buf[i] ^= key;
    }
}

static size_t key_len(uint8_t* key) {
    size_t ret = 0;
    while(key[ret] != 0) ret++;
    return ret;
}

static void swap(uint8_t* a, uint8_t* b) {
    uint8_t tmp = *a;
    *a = *b;
    *b = tmp;
}

void encrypt_rc4(uint8_t* buf, size_t size, uint8_t* key) {
    uint8_t S[256];
    unsigned i,j,k;
    size_t key_size = key_len(key);
    
    for(i = 0; i < 256; i++) {
        S[i] = i;
    }
    
    j = 0;
    for(i = 0; i < 256; i++) {
        j = (j + S[i] + key[i%key_size]) % 256;
        swap(&S[i], &S[j]);
    }
    
    i = 0;
    j = 0;
    for(k = 0; k < size; k++) {
        i = (i+1)%256;
        j = (j+S[i])%256;
        swap(&S[i], &S[j]);
        uint8_t index = (S[i] + S[j])%256;
        buf[k] ^= S[index];
    }
}

static void test(uint8_t* key) {
    uint8_t S[256];
    unsigned i,j,k;
    uint8_t* buf = (uint8_t *)0x60000000;
    size_t size = 23;
    
    size_t key_size = 0;
    while(key[key_size] != 0) key_size++;
    
    for(i = 0; i < 256; i++) {
        S[i] = i;
    }
    
    j = 0;
    for(i = 0; i < 256; i++) {
        j = (j + S[i] + key[i%key_size]) % 256;
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    
    i = 0;
    j = 0;
    for(k = 0; k < size; k++) {
        i = (i+1)%256;
        j = (j+S[i])%256;
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        uint8_t index = (S[i] + S[j])%256;
        buf[k] ^= S[index];
    }
}
