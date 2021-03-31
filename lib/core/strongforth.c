#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>
#include <unistd.h>
#include <crypto/hashes/sha2_routines.h>

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
#define STH_SECRETBOX_CLEN (64)
#define STH_SECRETBOX_MLEN (28)

/* common syscall ids */
#define STF_SYSCALL_EXIT ZF_SYSCALL_USER + 0
#define STF_SYSCALL_SIN ZF_SYSCALL_USER + 1
#define STF_SYSCALL_INCLUDE ZF_SYSCALL_USER + 2
#define STF_SYSCALL_SAVE ZF_SYSCALL_USER + 3
#define STF_SYSCALL_B32IN ZF_SYSCALL_USER + 4
#define STF_SYSCALL_B32TELL ZF_SYSCALL_USER + 5
#define STF_SYSCALL_GETSTATUS ZF_SYSCALL_USER + 6
#define STF_SYSCALL_SECRETBOX_KEYGEN ZF_SYSCALL_USER + 7
#define STF_SYSCALL_SECRETBOX_ENCRYPT ZF_SYSCALL_USER + 8
#define STF_SYSCALL_SECRETBOX_DECRYPT ZF_SYSCALL_USER + 9
#define STF_SYSCALL_MEMZERO ZF_SYSCALL_USER + 10
#define STF_SYSCALL_RANDOM_FILL ZF_SYSCALL_USER + 11
#define STF_SYSCALL_KDF ZF_SYSCALL_USER + 12
#define STF_SYSCALL_MEMCOPY ZF_SYSCALL_USER + 13
#define STF_SERVER_SYSCALL_SHA256_INIT ZF_SYSCALL_USER + 14
#define STF_SERVER_SYSCALL_SHA256_UPDATE ZF_SYSCALL_USER + 15
#define STF_SERVER_SYSCALL_SHA256_FINALIZE ZF_SYSCALL_USER + 16

/* syscall ranges */
#define STF_SYSCALLS_COMMON ZF_SYSCALL_USER + 20

sw_sha256_ctx g_sha256_ctx;

static zf_addr B32_INPUT = 0;

static char RETURN_BUF[STF_RETURN_BUF_LEN] = {0};
static size_t RETBUF_INDEX = 0;

static char* allot_retbuf (size_t len)
{
	if (RETBUF_INDEX + len > (sizeof(RETURN_BUF) - 2))
	{
		LOG("no space left in return buffer!");
		return NULL;
	}
        RETBUF_INDEX = RETBUF_INDEX + len;
	return RETURN_BUF + (RETBUF_INDEX - len);
}

static int retbuf_putchar (char c)
{
	if (RETBUF_INDEX > (sizeof(RETURN_BUF) - 2))
	{
		LOG("no space left in return buffer!");
		return 1;
	}
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
        LOG("error opening file '%s': %s\n", fname, strerror(errno));
	zf_abort(ZF_ABORT_NOT_A_WORD);
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
    size_t encoded_len = (((len * 8) + (5 - ((len * 8) % 5))) / 5);

    char *retbuf = allot_retbuf(encoded_len + 1);
    if (retbuf){
    	base32_encode(data, len, (uint8_t *) retbuf, encoded_len);
	memset(retbuf + encoded_len, ' ', 1);
    }
}

static inline void stf_crypto_secretbox_keygen ()
{
    uint8_t *key_buf = NULL;
    uint8_t l = get_crypto_pointer (&key_buf, zf_pop());
    if (32 == l)
    {
        hydro_secretbox_keygen (key_buf);
    }

}

static inline void stf_crypto_secretbox_encrypt ()
{
    uint8_t *key_buf = NULL;
    uint8_t l = get_crypto_pointer (&key_buf, zf_pop());
    if (32 != l)
    {
        LOG ("key buff wrong size\n");
	zf_abort(ZF_ABORT_INTERNAL_ERROR);
        return;
    }


    uint32_t msg_id = zf_pop();

    uint8_t *m_buf = NULL;
    l = get_crypto_pointer (&m_buf, zf_pop());
    if (STH_SECRETBOX_MLEN != l)
    {
        LOG ("m buff wrong size\n");
	zf_abort(ZF_ABORT_INVALID_SIZE);
    }


    l = zf_pop();
    if (l > STH_SECRETBOX_MLEN)
    {
        LOG ("mlen wrong size\n");
	zf_abort(ZF_ABORT_INVALID_SIZE);
    }
    else if (l < STH_SECRETBOX_MLEN)
    {
        int padsize = hydro_pad(m_buf, l, STH_SECRETBOX_MLEN, STH_SECRETBOX_MLEN);
        if (STH_SECRETBOX_MLEN != padsize)
        {
            LOG ("padding fail %d\n", padsize);
	    zf_abort(ZF_ABORT_INTERNAL_ERROR);
        }
    }


    uint8_t *c_buf = NULL;
    l = get_crypto_pointer (&c_buf, zf_pop());
    if (STH_SECRETBOX_CLEN != l)
    {
        LOG ("ctext  fail fail\n");
	zf_abort(ZF_ABORT_INTERNAL_ERROR);
    }

    hydro_secretbox_encrypt(c_buf, m_buf, STH_SECRETBOX_MLEN,
                            msg_id, HYDRO_CONTEXT,
                            key_buf);
}

static inline void stf_crypto_secretbox_decrypt ()
{
    uint8_t *key_buf = NULL;
    uint8_t l = get_crypto_pointer (&key_buf, zf_pop());
    if (32 != l)
        return;

    uint32_t msg_id = zf_pop();

    uint8_t *m_buf = NULL;
    l = get_crypto_pointer (&m_buf, zf_pop());
    if (STH_SECRETBOX_MLEN != l)
        return;

    uint8_t *c_buf = NULL;
    l = get_crypto_pointer (&c_buf, zf_pop());
    if (STH_SECRETBOX_CLEN != l)
        return;

    int rc = hydro_secretbox_decrypt(m_buf, c_buf, STH_SECRETBOX_CLEN,
                                     msg_id, HYDRO_CONTEXT, key_buf);

    if (0 == rc)
    {
        ssize_t unpad =  (uint32_t)hydro_unpad(m_buf,
                                               STH_SECRETBOX_MLEN,
                                               STH_SECRETBOX_MLEN);
        if (-1 == unpad || unpad > 28)
        {
            /*  push max message size */
            zf_push (STH_SECRETBOX_MLEN);
        }
        else
        {
            zf_push ((uint32_t) unpad);
        }
    }
    else
    {
        fprintf (stdout, "decrypt failed\n");
        zf_push(0);
    }
}

static inline void stf_crypto_memzero ()
{
    uint8_t *buf = NULL;
    uint8_t l = get_crypto_pointer (&buf, zf_pop());

    hydro_memzero (buf, l);

}

static inline void stf_crypto_random_fill()
{
    uint8_t *buf = NULL;
    uint8_t l = get_crypto_pointer (&buf, zf_pop());

    if (buf)
        hydro_random_buf(buf, l);
}

static inline void stf_crypto_kdf()
{
    uint8_t *master_key = NULL;
    uint8_t l = get_crypto_pointer (&master_key, zf_pop());
    if (l != hydro_kdf_KEYBYTES)
    {
        fprintf(stderr, "invalid kdf keybytes\n");
        return;
    }


    uint32_t sub_key_id = zf_pop();

    uint8_t *sub_key = NULL;
    uint8_t skl = get_crypto_pointer (&sub_key, zf_pop());
    if (skl < 16 || skl > 64)
    {
        fprintf(stderr, "invalid subkey buffer\n");
        return;
    }

    hydro_kdf_derive_from_key(sub_key, skl, sub_key_id, HYDRO_CONTEXT, master_key);
}

static inline void stf_debug_copy_buf()
{
    uint8_t *a = NULL;
    uint8_t al = get_crypto_pointer (&a, zf_pop());

    uint8_t *b = NULL;
    uint8_t bl = get_crypto_pointer (&b, zf_pop());

    assert (al == bl);

    memcpy (b, a, bl);
}

static inline void stf_server_sha256_init(void)
{
        sw_sha256_init(&g_sha256_ctx);
}

static inline void stf_server_sha256_update(void)
{
        uint8_t *p;
        int p_len = get_crypto_pointer(&p, zf_pop());

        sw_sha256_update(&g_sha256_ctx, p, p_len);
}

static inline void stf_server_sha256_finalize(void)
{
        uint8_t *p;
        int p_len = get_crypto_pointer(&p, zf_pop());
        assert (32 == p_len);

        sw_sha256_final(&g_sha256_ctx, p);


        sw_sha256_update(&g_sha256_ctx, p, p_len);
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

    		case STF_SYSCALL_SECRETBOX_KEYGEN:
			stf_crypto_secretbox_keygen();
			break;

    		case STF_SYSCALL_SECRETBOX_ENCRYPT:
    			stf_crypto_secretbox_encrypt();
    			break;

    		case STF_SYSCALL_SECRETBOX_DECRYPT:
    			stf_crypto_secretbox_decrypt();
    			break;

    		case STF_SYSCALL_MEMZERO:
    			stf_crypto_memzero();
   			break;

    		case STF_SYSCALL_RANDOM_FILL:
    			stf_crypto_random_fill();
    			break;

    		case STF_SYSCALL_KDF:
   			stf_crypto_kdf();
    			break;

		case STF_SYSCALL_MEMCOPY:
			stf_debug_copy_buf();
			break;

		case STF_SERVER_SYSCALL_SHA256_INIT:
			stf_server_sha256_init();
			break;

		case STF_SERVER_SYSCALL_SHA256_UPDATE:
			stf_server_sha256_update();
			break;

		case STF_SERVER_SYSCALL_SHA256_FINALIZE:
			stf_server_sha256_finalize();
			break;

    	    	default:
    	    		LOG("err: unhandled syscall %d\n", id);
			zf_abort(ZF_ABORT_NOT_A_WORD);
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
	LOG("\033[1;30m");
#ifdef STF_LOGGING
	vfprintf(stdout, fmt, va);
#endif
	LOG("\033[0m");
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
	if (dict_path != NULL)
		stf_include(dict_path);

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
	stf_eval_resp_t resp;

	reset_retbuf();
	zf_result rv = zf_eval(buf);

#ifdef STF_LOGGING
	const char *msg  = NULL;
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

	if (rv != ZF_OK)
		LOG("err: %s\n", msg);
#endif

	resp.rc = rv;
	resp.stf_status = get_strongforth_status();

	return resp;
}
