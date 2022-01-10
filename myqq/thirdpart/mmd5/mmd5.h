#ifndef _MMD5_H_
#define _MMD5_H_
#ifdef __cplusplus
extern "C"
{
#endif
#include <stdint.h>
#include <string.h>
void make_md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);
#ifdef __cplusplus
}
#endif
#endif
