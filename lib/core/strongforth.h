#ifndef strongforth_h
#define strongforth_h

#if defined(__unix__)
#include <cryptoauthlib/cryptoauthlib.h>
#else
#include "cryptoauthlib.h"
#endif
#include "strongforth_conf.h"

typedef struct stf_eval_resp {
	uint32_t rc;
	uint32_t stf_status;
} stf_eval_resp_t;

uint8_t stf_retbuf_copy (char *buf, size_t len);
char *stf_get_retbuf ();
ATCA_STATUS stf_init (char *dict_path, ATCAIfaceCfg *cfg);
stf_eval_resp_t stf_eval (const char *buf);

#endif
