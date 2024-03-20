#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "neon_wrapper.h"

#if defined(__ARM_NEON)
    #include <arm_neon.h>
#elif defined(__SSE2__)
    #include <emmintrin.h>
#endif

void neon_xor(const unsigned char* a, const unsigned char* b, unsigned char* result, int length) {
    int i = 0;
    // NEON implementation
    #if defined(__ARM_NEON)
        for (; i <= length - 16; i += 16) {
            uint8x16_t va = vld1q_u8(&a[i]);
            uint8x16_t vb = vld1q_u8(&b[i]);
            uint8x16_t vr = veorq_u8(va, vb);
            vst1q_u8(&result[i], vr);
        }
        for (; i < length; ++i) {
            result[i] = a[i] ^ b[i % 16];
        }
    // SSE2 implementation
    #elif defined(__SSE2__)
        for (; i <= length - 16; i += 16) {
            __m128i va = _mm_loadu_si128((__m128i const*)&a[i]);
            __m128i vb = _mm_loadu_si128((__m128i const*)&b[i]);
            __m128i vr = _mm_xor_si128(va, vb);
            _mm_storeu_si128((__m128i*)&result[i], vr);
        }
        for (; i < length; ++i) {
            result[i] = a[i] ^ b[i % 16];
        }
    // Default implementation
    #else
        for (; i < length; ++i) {
            result[i] = a[i] ^ b[i];
        }
    #endif
}


static int rand_int(int n) {
    int limit = RAND_MAX - RAND_MAX % n;
    int rnd;

    do {
        rnd = rand();
    } while (rnd >= limit);
    return rnd % n;
}

void shuffle(char *array, int n) {
    int i, j, tmp;
    for (i = n - 1; i > 0; i--) {
        j = rand_int(i + 1);
        tmp = array[j];
        array[j] = array[i];
        array[i] = tmp;
    }
}

// This function is used to expand the key to the size of the input data.
// This implementation is identical to the implementation in the C-SDK code for XQ for parity.
void expand_key(char* in_key, char* out_key, int new_len) {
    int original_len = (int) strlen(in_key);
    int current_len = original_len;

    // If the key is already a size we need, simply shuffle it.
    if ( current_len > new_len ) {
        memccpy( out_key, in_key, '\0', new_len );
        shuffle( out_key, new_len );
        return;
    }

    char* c = out_key;
    srand((unsigned int)time(NULL));
    current_len = 0;

    while (current_len < new_len)  {
        int remaining = new_len - current_len;

        if ( remaining > original_len ) {
            remaining = original_len;
        }
        memccpy(c, in_key, '\0', remaining);
        c += remaining;
        current_len += remaining;
    }

    shuffle( out_key , new_len );
    return;
}
