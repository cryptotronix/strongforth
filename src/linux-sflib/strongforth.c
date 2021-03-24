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
#include <unistd.h>

#include "strongforth.h"
#include "base32.h"

zf_addr B32_INPUT = 0;

static char RETURN_BUF[300] = {0};
static size_t RETBUF_INDEX = 0;

static char* allot_retbuf (size_t len)
{
	if (RETBUF_INDEX + len> (sizeof(RETURN_BUF) - 2))
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

uint8_t retbuf_copy (char *buf, size_t len)
{
	if (len > sizeof(RETURN_BUF))
		return 1;
	memcpy(buf, RETURN_BUF, len);
	return 0;
}

char *get_retbuf ()
{
	return RETURN_BUF;
}

static uint8_t get_crypto_pointer(uint8_t **buf, zf_addr addr)
{
    uint8_t len = 0;
    /* gets the length */
    dict_get_bytes(addr, &len, 1);
    /* get the actual data */
    *buf = dict_get_pointer(addr + 1, len);
    return len;
}

static inline void stf_print()
{
	char *retbuf;
	char cell[11] = {0};
	int len = snprintf(cell, 11, ZF_CELL_FMT, zf_pop());
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
static inline void include(const char *fname)
{
	char buf[256];

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

static inline void save(const char *fname)
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

static inline void tell(void)
{
    zf_cell len = zf_pop();
    void *buf = (uint8_t *)zf_dump(NULL) + (int)zf_pop();
    char *retbuf = allot_retbuf(len);
    if (retbuf != NULL)
    	memcpy(retbuf, buf, len);
}

static inline void decimal_tell(void)
{
    int i = 0;
    uint8_t *data;
    zf_addr addr = zf_pop();
    zf_cell len = get_crypto_pointer(&data, addr);
    while (i < len)
    {
        fprintf(stdout, "%d ", *(data + i++));
    }
}

static inline void b32in(void)
{
    zf_addr addr = zf_pop();
    /* set global b32 input flag */
    B32_INPUT = addr;
}

static inline void b32tell(void)
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

static inline void get_random(void)
{
    zf_addr addr = zf_pop();
    ATCA_STATUS status = atcab_random(dict_get_pointer(addr + 1, 32));
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_random() failed: %02x\r\n", status);
    }
}

static inline void get_counter(void)
{
    uint32_t counter_val;
    ATCA_STATUS status = atcab_counter_read(1, &counter_val);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_counter_read() failed: %02x\r\n", status);
        return;
    }

    zf_push(counter_val);
}

static inline void get_counter_inc(void)
{
    uint32_t counter_val;
    ATCA_STATUS status = atcab_counter_increment(1, &counter_val);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_counter_increment() failed: %02x\r\n", status);
        return;
    }

    zf_push(counter_val);
}

static inline void do_ecdsa_sign(void)
{
    uint8_t *sig;
    zf_addr sig_addr = zf_pop();
    zf_cell siglen = get_crypto_pointer(&sig, sig_addr);

    zf_cell pri_key_id = zf_pop();

    uint8_t *digest;
    zf_addr dig_addr = zf_pop();
    zf_cell diglen = get_crypto_pointer(&digest, dig_addr);

    if (siglen != 64)
    {
        fprintf(stderr, "sig buf not 64 bytes.");
        return;
    }

    if (diglen != 32)
    {
        fprintf(stderr, "digest buf not 32 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_sign(pri_key_id, digest, sig);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_sign() failed: %02x\r\n", status);
    }
}

static inline void do_ecdsa_verify(void)
{
    uint8_t *sig;
    zf_addr sig_addr = zf_pop();
    zf_cell siglen = get_crypto_pointer(&sig, sig_addr);

    zf_cell pub_key_id = zf_pop();

    uint8_t *digest;
    zf_addr dig_addr = zf_pop();
    zf_cell diglen = get_crypto_pointer(&digest, dig_addr);

    int8_t pass = 0;

    if (siglen != 64)
    {
        fprintf(stderr, "sig buf not 64 bytes.");
        return;
    }

    if (diglen != 32)
    {
        fprintf(stderr, "digest buf not 32 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_verify_stored(digest, sig, pub_key_id, (bool *)&pass);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_verify_extern() failed: %02x\r\n", status);
        return;
    }

    zf_push(pass ? -1 : 0);
}

static inline void get_pubkey(void)
{
    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t len = get_crypto_pointer(&pubkey, pk_addr);
    if (len != 64)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_get_pubkey(zf_pop(), pubkey);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_get_pubkey() failed: %02x\r\n", status);
    }
}

static inline void set_pubkey(void)
{
    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t len = get_crypto_pointer(&pubkey, pk_addr);
    if (len != 64)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_write_pubkey(zf_pop(), pubkey);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_write_pubkey() failed: %02x\r\n", status);
    }
}

static inline void do_ecdh(void)
{
    uint8_t *sharsec;
    zf_addr shsc_addr = zf_pop();
    zf_cell shsclen = get_crypto_pointer(&sharsec, shsc_addr);

    zf_cell pri_key_id = zf_pop();

    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t pklen = get_crypto_pointer(&pubkey, pk_addr);

    if (pklen != 64)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    if (shsclen != 32)
    {
        fprintf(stderr, "sharsec buf not 32 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_ecdh(pri_key_id, pubkey, sharsec);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_ecdh() failed: %02x\r\n", status);
    }
}

static inline void get_serial(void)
{
    uint8_t *serial;
    zf_addr ser_addr = zf_pop();
    zf_cell serlen = get_crypto_pointer(&serial, ser_addr);

    if (serlen != 9)
    {
        fprintf(stderr, "serial buf not 9 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_read_serial_number(serial);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_serial_number() failed: %02x\r\n", status);
    }
}

static inline void prep_key_rotate(void)
{
    /* returning the rotating key */
    uint8_t *pubkey;
    uint8_t pklen = get_crypto_pointer(&pubkey, zf_pop());

    /* getting rand out */
    uint8_t *random;
    uint8_t ranlen = get_crypto_pointer(&random, zf_pop());

    /* getting seed */
    uint8_t *seed;
    uint8_t selen = get_crypto_pointer(&seed, zf_pop());

    uint16_t slot_config = 0;
    uint16_t key_config = 0;

    if (pklen != 64)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    if (selen != 20)
    {
        fprintf(stderr, "seed must be 20 bytes.");
        return;
    }

    if (ranlen != 32)
    {
        fprintf(stderr, "rand must be 32 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_nonce_rand(seed, random);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_nonce() failed: %02x\r\n", status);
        return;
    }

    status = atcab_read_pubkey(14, pubkey);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_pubkey() failed: %02x\r\n", status);
        return;
    }


    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1, 48, (uint8_t*) &slot_config, 1);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_bytes_zone() failed: %02x\r\n", status);
        return;
    }
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1, 49, (uint8_t*) &slot_config + 1, 1);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_bytes_zone() failed: %02x\r\n", status);
        return;
    }

    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1, 124, (uint8_t*) &key_config, 1);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_bytes_zone() failed: %02x\r\n", status);
        return;
    }
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1, 125, (uint8_t*) &key_config + 1, 1);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_bytes_zone() failed: %02x\r\n", status);
        return;
    }

    zf_push(slot_config);
    zf_push(key_config);
}

static inline void key_rotate(void)
{
    /* signature */
    uint8_t *sig;
    zf_cell siglen = get_crypto_pointer(&sig, zf_pop());

    /* get genkey data */
    uint8_t *gendata;
    zf_cell genlen = get_crypto_pointer(&gendata, zf_pop());

    /* get verifiaction data */
    uint8_t *verdata;
    zf_cell verlen = get_crypto_pointer(&verdata, zf_pop());

    zf_cell validate = zf_pop();

    bool is_verified = -1;

    if (siglen != 64)
    {
        fprintf(stderr, "sig buf not 64 bytes.");
        return;
    }

    if (genlen != 3)
    {
        fprintf(stderr, "gendata buf not 3 bytes.");
        return;
    }

    if (verlen != 19)
    {
        fprintf(stderr, "verdata buf not 19 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PUBKEY_DIGEST, 14, gendata, NULL);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_genkey_base() failed: %02x\r\n", status);
        return;
    }

    if (validate == 0)
    {
        status = atcab_verify_validate(14, sig, verdata, &is_verified);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "atcab_verify_validate() failed: %02x\r\n", status);
            return;
        }
    }
    else if (validate == -1)
    {
        status = atcab_verify_invalidate(14, sig, verdata, &is_verified);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "atcab_verify_invalidate() failed: %02x\r\n", status);
            return;
        }
    }
    else
    {
        fprintf(stderr, "err: valid must be true(0) or false(-1)");
        return;
    }

    zf_push(is_verified ? -1 : 0);
}

static inline void read_pubkey_slot(void)
{
    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t pklen = get_crypto_pointer(&pubkey, pk_addr);

    if (pklen != 64)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_read_pubkey(zf_pop(), pubkey);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_read_pubkey() failed: %02x\r\n", status);
    }
}

/*
 * Sys callback function
 */
zf_input_state zf_host_sys(zf_syscall_id id, const char *input)
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
			tell();
			break;

		/* Application specific callbacks */
		case ZF_SYSCALL_USER + 0:
            		exit(0);
			break;

		case ZF_SYSCALL_USER + 1:
			zf_push(sin(zf_pop()));
			break;

#if defined(__unix__)
		case ZF_SYSCALL_USER + 2:
			if(input == NULL) {
				return ZF_INPUT_PASS_WORD;
			}
			include(input);
			break;

		case ZF_SYSCALL_USER + 3:
			save("zforth.save");
			break;
#endif

		case ZF_SYSCALL_USER + 4:
			decimal_tell();
			break;

		case ZF_SYSCALL_USER + 5:
			b32in();
			break;

		case ZF_SYSCALL_USER + 6:
			b32tell();
			break;

		case ZF_SYSCALL_USER + 7:
			/* TODO remove entirely */
			/* cal_init(); */
			break;

		case ZF_SYSCALL_USER + 8:
			get_random();
			break;

		case ZF_SYSCALL_USER + 9:
			get_counter();
			break;

		case ZF_SYSCALL_USER + 10:
			get_counter_inc();
			break;

		case ZF_SYSCALL_USER + 11:
			do_ecdsa_sign();
			break;

		case ZF_SYSCALL_USER + 12:
			do_ecdsa_verify();
			break;

		case ZF_SYSCALL_USER + 13:
			get_pubkey();
			break;

		case ZF_SYSCALL_USER + 14:
			set_pubkey();
			break;

		case ZF_SYSCALL_USER + 15:
			do_ecdh();
			break;

		case ZF_SYSCALL_USER + 16:
		    zf_push(strongheld_status_get());
		    break;

		case ZF_SYSCALL_USER + 17:
		    get_serial();
		    break;

		case ZF_SYSCALL_USER + 18:
		    prep_key_rotate();
		    break;

		case ZF_SYSCALL_USER + 19:
		    key_rotate();
		    break;

		case ZF_SYSCALL_USER + 20:
		    read_pubkey_slot();
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


/*
 * Initialize both zForth and cryptoauthlib
 */
ATCA_STATUS stf_init (ATCAIfaceCfg *cfg)
{
	zf_init(0);
	// TODO we will not want to bootstrap in future,
	// we need to provide a dict
	zf_bootstrap();
	include("../../forth/sfsmall.zf");

	return atcab_init(cfg);
}


/*
 * Evaluate buffer with code
 */

STF_EVAL_RESP stf_eval (const char *buf)
{
	const char *msg  = NULL;
	char *retbuf = NULL;

	STF_EVAL_RESP resp;

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
		memcpy(retbuf, msg, strlen(msg) + 1);
	}

	resp.evalrc = rv;
	resp.sf_status = strongheld_status_get();

	return resp;
}
