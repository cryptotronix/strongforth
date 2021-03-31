#ifndef server_h
#define server_h

#include <crypto/hashes/sha2_routines.h>

#include "zforth.h"

void stf_server_sys(zf_syscall_id id, const char *input);

#endif
