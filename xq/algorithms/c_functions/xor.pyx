# cython: language_level=3
cimport cython

cdef extern from "neon_wrapper.h":
    void neon_xor(const unsigned char* a, const unsigned char* b, unsigned char* result, int length)
    void expand_key(char* in_key, char* out_key, int new_len)

@cython.boundscheck(False)
@cython.wraparound(False)
def xor_simd_neon_python(bytes aa, bytes bb):
    cdef int real_size = len(aa)
    cdef int key_size = len(bb)
    cdef bytearray expanded_bb = bytearray(real_size)

    if key_size < real_size:
        expand_key(bb, expanded_bb, real_size)
        bb = bytes(expanded_bb)
    else:
        bb = bb[:real_size]

    cdef bytearray result = bytearray(real_size)
    neon_xor(aa, bb, result, real_size)

    return bytes(result), bb
