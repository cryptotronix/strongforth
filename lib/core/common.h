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

/* commented out until used
void set_strongforth_status(zf_cell val)
*/

zf_cell get_strongforth_status();

uint8_t get_crypto_pointer(uint8_t **buf, zf_addr addr);
#endif
