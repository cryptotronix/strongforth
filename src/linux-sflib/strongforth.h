#include <cryptoauthlib/cryptoauthlib.h>
#include "zforth.h"

typedef struct eval_resp {
	uint8_t evalrc;
	uint8_t sf_status;
} STF_EVAL_RESP;

uint8_t retbuf_copy (char *buf, size_t len);
char *get_retbuf ();
ATCA_STATUS stf_init (ATCAIfaceCfg *cfg);
STF_EVAL_RESP stf_eval (const char *buf);
