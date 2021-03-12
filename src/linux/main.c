
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

#include <cryptoauthlib/cryptoauthlib.h>

#ifdef USE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "zforth.h"
#include "base32.h"

zf_addr B32_INPUT = 0;

ATCAIfaceCfg cfg_ateccx08a_kithid_default = {
    .iface_type                  = ATCA_HID_IFACE,
    .devtype                     = ATECC608,
    {
        .atcahid.dev_interface   = ATCA_KIT_AUTO_IFACE,
        .atcahid.dev_identity    = 0,
        .atcahid.idx             = 0,
        .atcahid.vid             = 0x03EB,
        .atcahid.pid             = 0x2312,
        .atcahid.packetsize      = 64,
    }
};

static zf_cell read_crypto_addr(uint8_t **buf, zf_addr addr)
{
    zf_cell len = 0;
    /* gets the length */
    dict_get_bytes(addr, &len, sizeof(zf_cell));
    /* get the actual data */
    *buf = malloc(len);
    if (*buf == NULL)
        zf_abort(ZF_ABORT_INTERNAL_ERROR);
    dict_get_bytes(addr + sizeof(zf_cell), *buf, len);
    return len;
}

static void write_crypto_addr(zf_addr addr, const uint8_t *buf, zf_cell len)
{
    dict_put_bytes(addr, &len, sizeof(zf_cell));
    dict_put_bytes(addr + sizeof(zf_cell), buf, len);
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
 * Load dictionary
 */

static void load(const char *fname)
{
	size_t len;
	void *p = zf_dump(&len);
	FILE *f = fopen(fname, "rb");
	if(f) {
		fread(p, 1, len, f);
		fclose(f);
	} else {
		perror("read");
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
			putchar((char)zf_pop());
			fflush(stdout);
			break;

		case ZF_SYSCALL_PRINT:
			printf(ZF_CELL_FMT " ", zf_pop());
			break;

		case ZF_SYSCALL_TELL: {
			zf_cell len = zf_pop();
			void *buf = (uint8_t *)zf_dump(NULL) + (int)zf_pop();
			(void)fwrite(buf, 1, len, stdout);
			fflush(stdout); }
			break;


		/* Application specific callbacks */

		case ZF_SYSCALL_USER + 0:
			printf("\n");
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
                        int i = 0;
                        uint8_t *data;
                        zf_addr addr = zf_pop();
                        zf_cell len = read_crypto_addr(&data, addr);
                        while (i < len)
                            fprintf(stdout, "%d ", *(data + i++));
			fflush(stdout);
                        free(data); }
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
                        uint8_t *data;
                        zf_addr addr = zf_pop();
                        zf_cell len = read_crypto_addr(&data, addr);
                        uint8_t output[104];

                        count = base32_encode(data, len, output, 104);
                        free(data);
                        if (count > 0)
                            printf("%s", output);
                        else
                            fprintf(stderr, "incorrectly encoded.\n");
			fflush(stdout); }
			break;

                /* ATCA INIT */
		case ZF_SYSCALL_USER + 7: {
                    ATCA_STATUS status = ATCA_GEN_FAIL;

                    status = atcab_init(&cfg_ateccx08a_kithid_default);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_init() failed: %02x\r\n", status);
                    }
		    break;

                /* ATCA RANDOM */
		case ZF_SYSCALL_USER + 8: {
                    zf_addr addr = zf_pop();
                    zf_addr len = 32;
                    ATCA_STATUS status = ATCA_GEN_FAIL;
                    uint8_t randomnum[32];

                    status = atcab_random(randomnum);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_random() failed: %02x\r\n", status);
                    else
                    {
                        write_crypto_addr(addr, randomnum, len);
                        zf_push(addr);
                    } }
	            break;

                /* ATCA COUNTER READ */
		case ZF_SYSCALL_USER + 9: {
                    ATCA_STATUS status = ATCA_GEN_FAIL;
                    uint32_t counter_val;

                    status = atcab_counter_read(1, &counter_val);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_counter_read() failed: %02x\r\n", status);
                    else
                    {
                        zf_push(counter_val);
                    } }
	            break;

                /* ATCA COUNTER INCREMENT */
		case ZF_SYSCALL_USER + 10: {
                    ATCA_STATUS status = ATCA_GEN_FAIL;
                    uint32_t counter_val;

                    status = atcab_counter_increment(1, &counter_val);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_counter_increment() failed: %02x\r\n", status);
                    else
                    {
                        zf_push(counter_val);
                    } }
	            break;

                /* ATCA ECDSA SIGN */
		case ZF_SYSCALL_USER + 11: {
                    uint8_t sig[64];
                    zf_addr sig_addr = zf_pop();
                    uint8_t *msg;
                    zf_addr msg_addr = zf_pop();
                    zf_cell len = read_crypto_addr(&msg, msg_addr);
                    uint16_t priv_key_id = zf_pop();
                    ATCA_STATUS status = ATCA_GEN_FAIL;

                    if (len < 1)
                        fprintf(stderr, "nothing to sign.");
                    else
                    {
                        status = atcab_sign(priv_key_id, msg, sig);
                        if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_sign() failed: %02x\r\n", status);
                        else
                        {
                            write_crypto_addr(sig_addr, sig, 64);
                            zf_push(sig_addr);
                        }
                    } }
	            break;

                /* ATCA ECDSA VERIFY */
		case ZF_SYSCALL_USER + 12: {
                    zf_cell pass = 0;
                    uint8_t pubkey[64];
                    zf_addr pk_addr = zf_pop();
                    zf_cell pklen = read_crypto_addr((uint8_t**) &pubkey, pk_addr);
                    uint8_t sig[64];
                    zf_addr sig_addr = zf_pop();
                    zf_cell siglen = read_crypto_addr((uint8_t**) &sig, sig_addr);
                    uint8_t *msg;
                    zf_addr msg_addr = zf_pop();
                    zf_cell msglen = read_crypto_addr((uint8_t**) &msg, msg_addr);
                    ATCA_STATUS status = ATCA_GEN_FAIL;

                    if (pklen < 1)
                        fprintf(stderr, "no public key.");
                    else if (siglen < 1)
                        fprintf(stderr, "no signature.");
                    else if (msglen < 1)
                        fprintf(stderr, "no digest.");
                    else
                    {
                        status = atcab_verify_extern(msg, sig, pubkey, (bool *)&pass);
                        if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_verify_extern() failed: %02x\r\n", status);
                        else
                            zf_push(pass);
                    } }
	            break;

                /* ATCA GET PUB KEY */
		case ZF_SYSCALL_USER + 13: {
                    uint8_t pubkey[64];
                    zf_addr pk_addr = zf_pop();
                    uint16_t priv_key_id = zf_pop();
                    ATCA_STATUS status = ATCA_GEN_FAIL;

                    status = atcab_get_pubkey(priv_key_id, pubkey);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_genkey() failed: %02x\r\n", status);
                    else
                    {
                        write_crypto_addr(pk_addr, pubkey, 64);
                        zf_push(pk_addr);
                    } }
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
        uint8_t b32buf[64];
        zf_cell b32len = 0;
        zf_addr addr;

        if (B32_INPUT != 0)
        {
                addr = B32_INPUT;
                B32_INPUT = 0;

                b32len = base32_decode((const uint8_t*) buf, b32buf, 64);
                if (b32len > 0)
                        write_crypto_addr(addr, b32buf, b32len);
                else
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


void usage(void)
{
	fprintf(stderr,
		"usage: zfort [options] [src ...]\n"
		"\n"
		"Options:\n"
		"   -h         show help\n"
		"   -t         enable tracing\n"
		"   -l FILE    load dictionary from FILE\n"
	);
}


/*
 * Main
 */

int main(int argc, char **argv)
{
	int i;
	int c;
	int trace = 0;
	int line = 0;
	const char *fname_load = NULL;

	/* Parse command line options */

	while((c = getopt(argc, argv, "hl:t")) != -1) {
		switch(c) {
			case 't':
				trace = 1;
				break;
			case 'l':
				fname_load = optarg;
				break;
			case 'h':
				usage();
				exit(0);
		}
	}

	argc -= optind;
	argv += optind;


	/* Initialize zforth */

	zf_init(trace);


	/* Load dict from disk if requested, otherwise bootstrap fort
	 * dictionary */

	if(fname_load) {
		load(fname_load);
	} else {
		zf_bootstrap();
	}


	/* Include files from command line */

	for(i=0; i<argc; i++) {
		include(argv[i]);
	}


	/* Interactive interpreter: read a line using readline library,
	 * and pass to zf_eval() for evaluation*/

#ifdef USE_READLINE

	read_history(".zforth.hist");

	for(;;) {

		char *buf = readline("");
		if(buf == NULL) break;

		if(strlen(buf) > 0) {

			do_eval("stdin", ++line, buf);
			printf("\n");

			add_history(buf);
			write_history(".zforth.hist");

		}

	}
#else
	for(;;) {
		char buf[4096];
		if(fgets(buf, sizeof(buf), stdin)) {
			do_eval("stdin", ++line, buf);
			printf("\n");
		} else {
			break;
		}
	}
#endif

	return 0;
}


/*
 * End
 */

