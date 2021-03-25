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
#include "zforth.h"

#define SERIAL_NUM_LEN 9
#define KEYGEN_CONFIG_LEN 3
#define VERIFY_CONFIG_LEN 19
#define NONCE_SEED_LEN 20

#define STF_SYSCALL_EXIT ZF_SYSCALL_USER + 0
#define STF_SYSCALL_SIN ZF_SYSCALL_USER + 1
#define STF_SYSCALL_INCLUDE ZF_SYSCALL_USER + 2
#define STF_SYSCALL_SAVE ZF_SYSCALL_USER + 3
#define STF_SYSCALL_DTELL ZF_SYSCALL_USER + 4
#define STF_SYSCALL_B32IN ZF_SYSCALL_USER + 5
#define STF_SYSCALL_B32TELL ZF_SYSCALL_USER + 6
#define STF_SYSCALL_INIT ZF_SYSCALL_USER + 7
#define STF_SYSCALL_GETRAND ZF_SYSCALL_USER + 8
#define STF_SYSCALL_GETCOUNT ZF_SYSCALL_USER + 9
#define STF_SYSCALL_INCCOUNT ZF_SYSCALL_USER + 10
#define STF_SYSCALL_SIGN ZF_SYSCALL_USER + 11
#define STF_SYSCALL_VERIFY ZF_SYSCALL_USER + 12
#define STF_SYSCALL_GETPUB ZF_SYSCALL_USER + 13
#define STF_SYSCALL_SETPUB ZF_SYSCALL_USER + 14
#define STF_SYSCALL_ECDH ZF_SYSCALL_USER + 15
#define STF_SYSCALL_GETSTATUS ZF_SYSCALL_USER + 16
#define STF_SYSCALL_GETSERIAL ZF_SYSCALL_USER + 17
#define STF_SYSCALL_ROT1 ZF_SYSCALL_USER + 18
#define STF_SYSCALL_ROT3 ZF_SYSCALL_USER + 19
#define STF_SYSCALL_READPUB ZF_SYSCALL_USER + 20

static zf_cell STRONGFORTH_STATUS = 0;

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

/* commented out until used
static void set_strongforth_status(zf_cell val)
{
	STRONGFORTH_STATUS = val;
} */

static zf_cell get_strongforth_status()
{
	return STRONGFORTH_STATUS;
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

static inline void stf_decimal_tell(void)
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

static inline void stf_get_random(void)
{
    zf_addr addr = zf_pop();
    ATCA_STATUS status = atcab_random(dict_get_pointer(addr + 1, ATCA_KEY_SIZE));
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_random() failed: %02x\r\n", status);
    }
}

static inline void stf_get_counter(void)
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

static inline void stf_get_counter_inc(void)
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

static inline void stf_do_ecdsa_sign(void)
{
    uint8_t *sig;
    zf_cell siglen = get_crypto_pointer(&sig, zf_pop());

    zf_cell pri_key_id = zf_pop();

    uint8_t *digest;
    zf_cell diglen = get_crypto_pointer(&digest, zf_pop());

    if (siglen != ATCA_ECCP256_SIG_SIZE)
    {
        fprintf(stderr, "sig buf not 64 bytes.");
        return;
    }

    if (diglen != ATCA_SHA256_DIGEST_SIZE)
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

static inline void stf_do_ecdsa_verify(void)
{
    uint8_t *sig;
    zf_cell siglen = get_crypto_pointer(&sig, zf_pop());

    zf_cell pub_key_id = zf_pop();

    uint8_t *digest;
    zf_cell diglen = get_crypto_pointer(&digest, zf_pop());

    int8_t verified = 0;

    if (siglen != ATCA_ECCP256_SIG_SIZE)
    {
        fprintf(stderr, "sig buf not 64 bytes.");
        return;
    }

    if (diglen != ATCA_SHA256_DIGEST_SIZE)
    {
        fprintf(stderr, "digest buf not 32 bytes.");
        return;
    }

    ATCA_STATUS status = atcab_verify_stored(digest, sig, pub_key_id, (bool *)&verified);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_verify_extern() failed: %02x\r\n", status);
        return;
    }

    zf_push(verified ? -1 : 0);
}

static inline void stf_get_pubkey(void)
{
    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t len = get_crypto_pointer(&pubkey, pk_addr);
    if (len != ATCA_ECCP256_PUBKEY_SIZE)
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

static inline void stf_set_pubkey(void)
{
    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t len = get_crypto_pointer(&pubkey, pk_addr);
    if (len != ATCA_ECCP256_PUBKEY_SIZE)
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

static inline void stf_do_ecdh(void)
{
    uint8_t *sharsec;
    zf_cell shsclen = get_crypto_pointer(&sharsec, zf_pop());

    zf_cell pri_key_id = zf_pop();

    uint8_t *pubkey;
    uint8_t pklen = get_crypto_pointer(&pubkey, zf_pop());

    if (pklen != ATCA_ECCP256_PUBKEY_SIZE)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    if (shsclen != ATCA_KEY_SIZE)
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

static inline void stf_get_serial(void)
{
    uint8_t *serial;
    zf_cell serlen = get_crypto_pointer(&serial, zf_pop());

    if (serlen != SERIAL_NUM_LEN)
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

static inline void stf_prep_key_rotate(void)
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

    if (pklen != ATCA_ECCP256_PUBKEY_SIZE)
    {
        fprintf(stderr, "pubkey buf not 64 bytes.");
        return;
    }

    if (selen != NONCE_SEED_LEN)
    {
        fprintf(stderr, "seed must be 20 bytes.");
        return;
    }

    if (ranlen != ATCA_KEY_SIZE)
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

static inline void stf_key_rotate(void)
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

    if (siglen != ATCA_ECCP256_SIG_SIZE)
    {
        fprintf(stderr, "sig buf not 64 bytes.");
        return;
    }

    if (genlen != KEYGEN_CONFIG_LEN)
    {
        fprintf(stderr, "gendata buf not 3 bytes.");
        return;
    }

    if (verlen != VERIFY_CONFIG_LEN)
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

static inline void stf_read_pubkey_slot(void)
{
    uint8_t *pubkey;
    zf_addr pk_addr = zf_pop();
    uint8_t pklen = get_crypto_pointer(&pubkey, pk_addr);

    if (pklen != ATCA_ECCP256_PUBKEY_SIZE)
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

		case STF_SYSCALL_DTELL:
			stf_decimal_tell();
			break;

		case STF_SYSCALL_B32IN:
			stf_b32in();
			break;

		case STF_SYSCALL_B32TELL:
			stf_b32tell();
			break;

		case STF_SYSCALL_INIT:
			/* TODO remove entirely */
			/* cal_init(); */
			break;

		case STF_SYSCALL_GETRAND:
			stf_get_random();
			break;

		case STF_SYSCALL_GETCOUNT:
			stf_get_counter();
			break;

		case STF_SYSCALL_INCCOUNT:
			stf_get_counter_inc();
			break;

		case STF_SYSCALL_SIGN:
			stf_do_ecdsa_sign();
			break;

		case STF_SYSCALL_VERIFY:
			stf_do_ecdsa_verify();
			break;

		case STF_SYSCALL_GETPUB:
			stf_get_pubkey();
			break;

		case STF_SYSCALL_SETPUB:
			stf_set_pubkey();
			break;

		case STF_SYSCALL_ECDH:
			stf_do_ecdh();
			break;

		case STF_SYSCALL_GETSTATUS:
		    zf_push(get_strongforth_status());
		    break;

		case STF_SYSCALL_GETSERIAL:
		    stf_get_serial();
		    break;

		case STF_SYSCALL_ROT1:
		    stf_prep_key_rotate();
		    break;

		case STF_SYSCALL_ROT3:
		    stf_key_rotate();
		    break;

		case STF_SYSCALL_READPUB:
		    stf_read_pubkey_slot();
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
	stf_include("../../forth/sfsmall.zf");

	ATCA_STATUS stat = !ATCA_SUCCESS;
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
