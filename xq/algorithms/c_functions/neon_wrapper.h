// neon_operations.h
#ifndef NEON_OPERATIONS_H
#define NEON_OPERATIONS_H

void neon_xor(const unsigned char* a, const unsigned char* b, unsigned char* result, int length);
void expand_key(char* in_key, char* out_key, int new_len);

#endif // NEON_OPERATIONS_H
