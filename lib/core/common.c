#include "common.h"

static zf_cell STRONGFORTH_STATUS = 0;

/* commented out until used
void set_strongforth_status(zf_cell val)
{
	STRONGFORTH_STATUS = val;
} */

zf_cell get_strongforth_status()
{
	return STRONGFORTH_STATUS;
}

uint8_t get_crypto_pointer(uint8_t **buf, zf_addr addr)
{
    uint8_t len = 0;
    /* gets the length */
    dict_get_bytes(addr, &len, 1);
    /* get the actual data */
    *buf = dict_get_pointer(addr + 1, len);
    return len;
}
