#include <cryptoauthlib/cryptoauthlib.h>
#include "strongforth_conf.h"

typedef struct stf_eval_resp {
	uint32_t rc;
	uint32_t stf_status;
} stf_eval_resp_t;

uint8_t stf_retbuf_copy (char *buf, size_t len);
char *stf_get_retbuf ();
ATCA_STATUS stf_init (ATCAIfaceCfg *cfg);
stf_eval_resp_t stf_eval (const char *buf);
