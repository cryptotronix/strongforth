#ifndef common_h
#define common_h

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>

#include "zforth.h"

/* register lengths */
#define SERIAL_NUM_LEN 9
#define KEYGEN_CONFIG_LEN 3
#define VERIFY_CONFIG_LEN 19
#define NONCE_SEED_LEN 20

#ifdef STF_LOGGING
	#define LOG(...) fprintf(stdout, __VA_ARGS__)
#else
	#define LOG(...)
#endif

#ifdef ZF_CONST_DICTIONARY
stf_register_t STF_REGISTERS;

uint8_t get_register(uint8_t **buf, stf_register_id reg_id);
#else
uint8_t get_register(uint8_t **buf, zf_addr addr);
#endif

#endif
