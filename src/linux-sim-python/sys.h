#include <string.h>
#include <stdint.h>
#include "zforth.h"

char* allot_retbuf (size_t len);
int retbuf_putchar (char c);
uint8_t get_retbuf (char *buf, size_t len);
void reset_retbuf();
zf_result do_eval(const char *src, int line, const char *buf);
