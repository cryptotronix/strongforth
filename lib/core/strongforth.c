#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
//#include <getopt.h>
#include <math.h>
#include <unistd.h>

#include "strongforth.h"
#include "base32.h"
#include "hydrogen.h"
#include "common.h"

#if defined(STF_DEVICE)
#include "device.h"
#endif
#if defined(STF_SERVER)
#include "server.h"
#endif

/* libhydrogen defines */
#define HYDRO_CONTEXT "strongfo"
#define HYDRO_MLEN (28)
#define HYDRO_CLEN (HYDRO_MLEN + hydro_secretbox_HEADERBYTES)

/* common syscall ids */
#define STF_SYSCALL_EXIT ZF_SYSCALL_USER + 0
#define STF_SYSCALL_SIN ZF_SYSCALL_USER + 1
#define STF_SYSCALL_INCLUDE ZF_SYSCALL_USER + 2
#define STF_SYSCALL_SAVE ZF_SYSCALL_USER + 3
#define STF_SYSCALL_B32IN ZF_SYSCALL_USER + 4
#define STF_SYSCALL_B32TELL ZF_SYSCALL_USER + 5
#define STF_SYSCALL_GETSTATUS ZF_SYSCALL_USER + 6
#define STF_SYSCALL_HYDROENC ZF_SYSCALL_USER + 7
#define STF_SYSCALL_HYDRODEC ZF_SYSCALL_USER + 8

/* syscall ranges */
#define STF_SYSCALLS_COMMON ZF_SYSCALL_USER + 8

static zf_addr B32_INPUT = 0;

static char RETURN_BUF[STF_RETURN_BUF_LEN] = {0};
static size_t RETBUF_INDEX = 0;

static char* allot_retbuf (size_t len)
{
	if (RETBUF_INDEX + len > (sizeof(RETURN_BUF) - 2))
		return NULL;
        RETBUF_INDEX = RETBUF_INDEX + len;
	return RETURN_BUF + (RETBUF_INDEX - len);
}

static int retbuf_putchar (char c)
{
	if (RETBUF_INDEX > (sizeof(RETURN_BUF) - 2))
		return 1;
	RETURN_BUF[RETBUF_INDEX++] = c;
	return 0;
}

static void reset_retbuf()
{
	memset(RETURN_BUF, 0, sizeof(RETURN_BUF));
	RETBUF_INDEX = 0;
}

uint8_t stf_retbuf_copy (char *buf, size_t len)
{
	if (len > sizeof(RETURN_BUF))
		return 1;
	memcpy(buf, RETURN_BUF, len);
	return 0;
}

char *stf_get_retbuf ()
{
	return RETURN_BUF;
}

static inline void stf_print()
{
#define MAX_CELL_CHARS 11
	char *retbuf;
	char cell[MAX_CELL_CHARS] = {0};
	int len = snprintf(cell, sizeof(cell), ZF_CELL_FMT, zf_pop());
	if (len > 0 )
	{
		retbuf = allot_retbuf(strlen(cell) + 1);
		if (retbuf != NULL)
		{
			memcpy(retbuf, cell, strlen(cell));
			memset(retbuf + strlen(cell), ' ', 1);
		}
	}
}

#if defined(__unix__)
static inline void stf_include(const char *fname)
{
	char buf[STF_FILE_INPUT_BUF_LEN];

	FILE *f = fopen(fname, "rb");
	if (!f)
    {
        fprintf(stderr, "error opening file '%s': %s\n", fname, strerror(errno));
        return;
    }

    while (fgets(buf, sizeof(buf), f))
    {
        stf_eval(buf);
    }
    fclose(f);
}

static inline void stf_save(const char *fname)
{
	size_t len;
	void *p = zf_dump(&len);
	FILE *f = fopen(fname, "wb");
	if (f)
    {
		fwrite(p, 1, len, f);
		fclose(f);
	}
}
#endif

static inline void stf_tell(void)
{
    zf_cell len = zf_pop();
    void *buf = (uint8_t *)zf_dump(NULL) + (int)zf_pop();
    char *retbuf = allot_retbuf(len);
    if (retbuf != NULL)
    	memcpy(retbuf, buf, len);
}

static inline void stf_b32in(void)
{
    zf_addr addr = zf_pop();
    /* set global b32 input flag */
    B32_INPUT = addr;
}

static inline void stf_b32tell(void)
{
    zf_addr addr = zf_pop();
    uint8_t *data;
    zf_cell len = get_crypto_pointer(&data, addr);

    char *retbuf = allot_retbuf(len + 1);
    if (retbuf){
    	base32_encode(data, len, (uint8_t *) retbuf, len);
	memset(retbuf + len, ' ', 1);
    }
}

static inline void stf_hydro_encrypt(void)
{
    uint8_t *key;
    int l = get_crypto_pointer(&key, zf_pop());
    assert (hydro_secretbox_KEYBYTES == l);

    uint8_t *iv;
    l = get_crypto_pointer(&iv, zf_pop());
    assert (32 == l);

    int msg_id = zf_pop();

    uint8_t *m_;
    int mlen = get_crypto_pointer(&m_, zf_pop());
    assert (HYDRO_MLEN == mlen);

    uint8_t *c;
    l = get_crypto_pointer(&c, zf_pop());
    assert (HYDRO_CLEN == l);

    int rc = hydro_secretbox_encrypt_iv(c, m_, mlen, msg_id, HYDRO_CONTEXT, key, iv);
    assert (0==rc);
}

static inline void stf_hydro_decrypt(void)
{
    uint8_t *key;
    int l = get_crypto_pointer(&key, zf_pop());
    assert (hydro_secretbox_KEYBYTES == l);

    int msg_id = zf_pop();

    uint8_t *m_;
    int mlen = get_crypto_pointer(&m_, zf_pop());
    assert (HYDRO_MLEN == mlen);

    uint8_t *c;
    l = get_crypto_pointer(&c, zf_pop());
    assert (HYDRO_CLEN == l);

    int rc = hydro_secretbox_decrypt(m_, c, HYDRO_CLEN, msg_id, HYDRO_CONTEXT, key);

    if (0 == rc)
    {
        zf_push (~0);
    }
    else
    {
        zf_push (0);
    }
}

/*
 * Sys callback function
 */
zf_input_state zf_host_sys(zf_syscall_id id, const char *input)
{
    if ((int) id <= STF_SYSCALLS_COMMON)
    {
    	switch((int)id)
    	{
    	    	/* The core system callbacks */
    	    	case ZF_SYSCALL_EMIT:
    	    		retbuf_putchar((char)zf_pop());
    	    		break;

    	    	case ZF_SYSCALL_PRINT:
    	    		stf_print();
    	    		break;

    	    	case ZF_SYSCALL_TELL:
    	    		stf_tell();
    	    		break;

    	    	/* Application specific callbacks */
    	    	case STF_SYSCALL_EXIT:
    	        		exit(0);
    	    		break;

    	    	case STF_SYSCALL_SIN:
    	    		zf_push(sin(zf_pop()));
    	    		break;

#if defined(__unix__)
    	    	case STF_SYSCALL_INCLUDE:
    	    		if(input == NULL) {
    	    			return ZF_INPUT_PASS_WORD;
    	    		}
    	    		stf_include(input);
    	    		break;

    	    	case STF_SYSCALL_SAVE:
    	    		stf_save("zforth.save");
    	    		break;
#endif

		case STF_SYSCALL_B32IN:
			stf_b32in();
			break;

		case STF_SYSCALL_B32TELL:
			stf_b32tell();
			break;

		case STF_SYSCALL_GETSTATUS:
		    zf_push(get_strongforth_status());
		    break;

    	    	default:
    	    		printf("unhandled syscall %d\n", id);
    	    		break;
    	}
    }
    else
    {
#if defined(STF_DEVICE)
	stf_device_sys(id, input);
    	return ZF_INPUT_INTERPRET;
#endif
#if defined(STF_SERVER)
	stf_server_sys(id, input);
    	return ZF_INPUT_INTERPRET;
#endif
    }

    return ZF_INPUT_INTERPRET;
}

/*
 * Tracing output
 */

void zf_host_trace(const char *fmt, va_list va)
{
	fprintf(stderr, "\033[1;30m");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\033[0m");
}


/*
 * Parse number
 */

zf_cell zf_host_parse_num(const char *buf)
{
	zf_cell v;
        uint8_t *b32buf;
        int8_t b32len;
        int8_t decolen;
        zf_addr addr;

        if (B32_INPUT != 0)
        {
                addr = B32_INPUT;
                B32_INPUT = 0;

		b32len = get_crypto_pointer(&b32buf, addr);
                decolen = base32_decode((const uint8_t*) buf, b32buf, b32len);
                if (decolen < 1)
		        zf_abort(ZF_ABORT_NOT_A_WORD);
                v = addr;
        }
        else
        {
	        int r = sscanf(buf, "%d", &v);
	        if(r == 0) {
		        zf_abort(ZF_ABORT_NOT_A_WORD);
	        }
        }
	return v;
}


/*
 * Initialize both zForth and cryptoauthlib
 */
ATCA_STATUS stf_init (char *dict_path, ATCAIfaceCfg *cfg)
{
	zf_init(0);

	// TODO will not be bootstrapping and including in future, will use binary
	zf_bootstrap();
    
#if defined(__unix__)
	if (dict_path != NULL)
		stf_include(dict_path);
#endif
    
	ATCA_STATUS stat = ~ATCA_SUCCESS;
	if (cfg != NULL)
		stat = atcab_init(cfg);
	else
		stat = ATCA_SUCCESS;

	return stat;
}


/*
 * Evaluate buffer with code
 */

stf_eval_resp_t stf_eval (const char *buf)
{
	const char *msg  = NULL;
	char *retbuf = NULL;

	stf_eval_resp_t resp;

	reset_retbuf();

	zf_result rv = zf_eval(buf);

	switch(rv)
	{
		case ZF_OK: break;
		case ZF_ABORT_INTERNAL_ERROR: msg = "internal error"; break;
		case ZF_ABORT_OUTSIDE_MEM: msg = "outside memory"; break;
		case ZF_ABORT_DSTACK_OVERRUN: msg = "dstack overrun"; break;
		case ZF_ABORT_DSTACK_UNDERRUN: msg = "dstack underrun"; break;
		case ZF_ABORT_RSTACK_OVERRUN: msg = "rstack overrun"; break;
		case ZF_ABORT_RSTACK_UNDERRUN: msg = "rstack underrun"; break;
		case ZF_ABORT_NOT_A_WORD: msg = "not a word"; break;
		case ZF_ABORT_COMPILE_ONLY_WORD: msg = "compile-only word"; break;
		case ZF_ABORT_INVALID_SIZE: msg = "invalid size"; break;
		case ZF_ABORT_DIVISION_BY_ZERO: msg = "division by zero"; break;
		default: msg = "unknown error";
	}

	if (msg)
	{
		reset_retbuf();
		retbuf = allot_retbuf (strlen(msg));
		memcpy(retbuf, msg, strlen(msg));
	}

	resp.rc = rv;
	resp.stf_status = get_strongforth_status();

	return resp;
}
