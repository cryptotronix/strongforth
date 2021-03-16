
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>

#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zforth.h"
#include "base32.h"
#include "uECC.h"

zf_addr B32_INPUT = 0;

static uint8_t get_crypto_pointer(uint8_t **buf, zf_addr addr)
{
    uint8_t len = 0;
    /* gets the length */
    dict_get_bytes(addr, &len, 1);
    /* get the actual data */
    *buf = dict_get_pointer(addr + 1, len);
    return len;
}

char RETURN_BUF[256] = {0};
size_t RETBUF_INDEX = 0;

char* allot_retbuf (size_t len)
{
	if (RETBUF_INDEX + len > 254)
		return NULL;
        RETBUF_INDEX = RETBUF_INDEX + len;
	return RETURN_BUF + RETBUF_INDEX - len;
}

int retbuf_putchar (char c)
{
	if (RETBUF_INDEX > 254)
		return -1;
	RETURN_BUF[RETBUF_INDEX++] = c;
	return 0;
}

uint8_t get_retbuf (char *buf, size_t len)
{
	if (len > 256)
		return -1;
	memcpy(buf, RETURN_BUF, 256);
	return 0;
}

void reset_retbuf()
{
	memset(RETURN_BUF, 0, 256);
	RETBUF_INDEX = 0;
}


/*
 * Evaluate buffer with code, check return value and report errors
 */

zf_result do_eval(const char *src, int line, const char *buf)
{
	const char *msg = NULL;


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


	if(msg) {
		fprintf(stderr, "\033[31m");
		if(src) fprintf(stderr, "%s:%d: ", src, line);
		fprintf(stderr, "%s\033[0m\n", msg);
	}


	return rv;
}


/*
 * Load given forth file
 */

void include(const char *fname)
{
	char buf[256];


	FILE *f = fopen(fname, "rb");
	int line = 1;
	if(f) {
		while(fgets(buf, sizeof(buf), f)) {
			do_eval(fname, line++, buf);
		}
		fclose(f);
	} else {
		fprintf(stderr, "error opening file '%s': %s\n", fname, strerror(errno));
	}
}


/*
 * Save dictionary
 */

static void save(const char *fname)
{
	size_t len;
	void *p = zf_dump(&len);
	FILE *f = fopen(fname, "wb");
	if(f) {
		fwrite(p, 1, len, f);
		fclose(f);
	}
}

/*
 * Sys callback function
 */

zf_input_state zf_host_sys(zf_syscall_id id, const char *input)
{
	switch((int)id) {


		/* The core system callbacks */

		case ZF_SYSCALL_EMIT:
			retbuf_putchar((char)zf_pop());
			break;

		case ZF_SYSCALL_PRINT: {
			char *retbuf;
			char cell[11] = {0};
			int len = snprintf(cell, 11, ZF_CELL_FMT " ", zf_pop());
			if (len > 0 )
			{
				retbuf = allot_retbuf(strlen(cell));
				if (retbuf != NULL)
					memcpy(retbuf, cell, strlen(cell));
			}
			}
			break;

		case ZF_SYSCALL_TELL: {
			zf_cell len = zf_pop();
			void *buf = (uint8_t *)zf_dump(NULL) + (int)zf_pop();
			(void)fwrite(buf, 1, len, stdout);
			fflush(stdout); }
			break;


		/* Application specific callbacks */

		case ZF_SYSCALL_USER + 0:
			retbuf_putchar('\n');
			exit(0);
			break;

		case ZF_SYSCALL_USER + 1:
			zf_push(sin(zf_pop()));
			break;

		case ZF_SYSCALL_USER + 2:
			if(input == NULL) {
				return ZF_INPUT_PASS_WORD;
			}
			include(input);
			break;

		case ZF_SYSCALL_USER + 3:
			save("zforth.save");
			break;

                /* DECIMAL TELL */
		case ZF_SYSCALL_USER + 4: {

			}
			break;

                /* BASE 32 VALUE IN */
		case ZF_SYSCALL_USER + 5: {
                    zf_addr addr = zf_pop();
                    /* set global b32 input flag */
                    B32_INPUT = addr;
                    zf_push(addr);
                    }
	            break;

                /* BASE 32 TELL */
		case ZF_SYSCALL_USER + 6: {
                        int count = 0;
                        zf_addr addr = zf_pop();
                        uint8_t *data;
                        zf_cell len = get_crypto_pointer(&data, addr);

                        count = base32_emit(data, len);
                        if (count < 1)
			    zf_abort(ZF_ABORT_INTERNAL_ERROR);
			fflush(stdout); }
			break;

                /* ATCA INIT */
		case ZF_SYSCALL_USER + 7: {

                    }
		    break;

                /* ATCA RANDOM */
		case ZF_SYSCALL_USER + 8: {
			uint8_t *r;
			int b32len = get_crypto_pointer(&r, zf_pop());
			assert(32 == b32len);
			int rd = open("/dev/urandom", O_RDONLY);
            assert (rd > 0);

            ssize_t result = read(rd, r, 32);
            assert (result >= 0);

            }
	        break;

                /* ATCA COUNTER READ */
		case ZF_SYSCALL_USER + 9: {

                    }
	            break;

                /* ATCA COUNTER INCREMENT */
		case ZF_SYSCALL_USER + 10: {

                    }
	            break;

                /* ATCA ECDSA SIGN */
		case ZF_SYSCALL_USER + 11: {

			uint8_t *sig;
			int sig_len = get_crypto_pointer(&sig, zf_pop());
			uint8_t *prikey;
			int prikey_len = get_crypto_pointer(&prikey, zf_pop());
			uint8_t *digest;
			int digest_len = get_crypto_pointer(&digest, zf_pop());

			assert(sig_len == 64);
			assert(prikey_len == 32);
			assert(digest_len == 32);

			int rc = uECC_sign(prikey, digest, sig);
			assert(1 == rc);
		}
				break;

                /* ATCA ECDSA VERIFY */
		case ZF_SYSCALL_USER + 12: {

			uint8_t *sig;
			int sig_len = get_crypto_pointer(&sig, zf_pop());
			uint8_t *pubkey;
			int pubkey_len = get_crypto_pointer(&pubkey, zf_pop());
			uint8_t *digest;
			int digest_len = get_crypto_pointer(&digest, zf_pop());

			assert(sig_len == 64);
			assert(pubkey_len == 64);
			assert(digest_len == 32);

			int rc = uECC_verify(pubkey, digest, sig);

			if (1 == rc)
				zf_push(~0);
			else
				zf_push(0);
		}
	            break;

                /* ATCA GET PUB KEY */
		case ZF_SYSCALL_USER + 13: { }
	            break;

                /* ATCA SET PUB KEY */
		case ZF_SYSCALL_USER + 14: {
                    }
	            break;
		/* ECDH */
		case ZF_SYSCALL_USER + 15: {

			uint8_t *sharedsec;
			int sharedsec_len = get_crypto_pointer(&sharedsec, zf_pop());
			uint8_t *prikey;
			int prikey_len = get_crypto_pointer(&prikey, zf_pop());
			uint8_t *pubkey;
			int pubkey_len = get_crypto_pointer(&pubkey, zf_pop());

			assert(pubkey_len == 64);
			assert(prikey_len == 32);
			assert(sharedsec_len == 32);

			int rc = uECC_shared_secret(pubkey, prikey, sharedsec);
			assert(1 == rc);
		}
		break;
		case ZF_SYSCALL_USER + 30:
		{

			uint8_t *pubkey;
			int pubkey_len = get_crypto_pointer(&pubkey, zf_pop());
			uint8_t *prikey;
			int prikey_len = get_crypto_pointer(&prikey, zf_pop());
			assert(pubkey_len == 64);
			assert(prikey_len == 32);

			int rc = uECC_make_key(pubkey, prikey);
			assert(1 == rc);
		}
				break;

		default:
			printf("unhandled syscall %d\n", id);
			break;
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
