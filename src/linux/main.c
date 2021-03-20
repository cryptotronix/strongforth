
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
        .atcahid.dev_interface   = ATCA_KIT_I2C_IFACE,
        .atcahid.dev_identity    = 0x6C,
        .atcahid.idx             = 0,
        .atcahid.vid             = 0x03EB,
        .atcahid.pid             = 0x2312,
        .atcahid.packetsize      = 64,
    }
};

static uint8_t get_crypto_pointer(uint8_t **buf, zf_addr addr)
{
    uint8_t len = 0;
    /* gets the length */
    dict_get_bytes(addr, &len, 1);
    /* get the actual data */
    *buf = dict_get_pointer(addr + 1, len);
    return len;
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
        ATCA_STATUS status = ATCA_GEN_FAIL;
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
                        zf_cell len = get_crypto_pointer(&data, addr);
                        while (i < len)
                            fprintf(stdout, "%d ", *(data + i++));
			fflush(stdout);
                        }
			break;

                /* BASE 32 VALUE IN */
		case ZF_SYSCALL_USER + 5: {
                    zf_addr addr = zf_pop();
                    /* set global b32 input flag */
                    B32_INPUT = addr;
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
                            printf(" ERROR");
			fflush(stdout); }
			break;

                /* ATCA INIT */
		case ZF_SYSCALL_USER + 7: {
                    status = atcab_init(&cfg_ateccx08a_kithid_default);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_init() failed: %02x\r\n", status);
                    }
		    break;

                /* ATCA RANDOM */
		case ZF_SYSCALL_USER + 8: {
                    zf_addr addr = zf_pop();
                    status = atcab_random(dict_get_pointer(addr + 1, 32));
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_random() failed: %02x\r\n", status);
                    }
	            break;

                /* ATCA COUNTER READ */
		case ZF_SYSCALL_USER + 9: {
                    uint32_t counter_val;
                    status = atcab_counter_read(1, &counter_val);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_counter_read() failed: %02x\r\n", status);
                    else
                        zf_push(counter_val);
                    }
	            break;

                /* ATCA COUNTER INCREMENT */
		case ZF_SYSCALL_USER + 10: {
                    uint32_t counter_val;
                    status = atcab_counter_increment(1, &counter_val);
                    if (status != ATCA_SUCCESS)
                        fprintf(stderr, "atcab_counter_increment() failed: %02x\r\n", status);
                    else
                        zf_push(counter_val);
                    }
	            break;

                /* ATCA ECDSA SIGN */
		case ZF_SYSCALL_USER + 11: {
                    uint8_t *sig;
                    zf_addr sig_addr = zf_pop();
                    zf_cell siglen = get_crypto_pointer(&sig, sig_addr);

                    zf_cell pri_key_id = zf_pop();

                    uint8_t *digest;
                    zf_addr dig_addr = zf_pop();
                    zf_cell diglen = get_crypto_pointer(&digest, dig_addr);

		    if (siglen != 64)
                    	fprintf(stderr, "sig buf not 64 bytes.");
		    else if (diglen != 32)
                    	fprintf(stderr, "digest buf not 32 bytes.");
		    else
		    {
                    	status = atcab_sign(pri_key_id, digest, sig);
                    	if (status != ATCA_SUCCESS)
                    	    fprintf(stderr, "atcab_sign() failed: %02x\r\n", status);
		    } }
	            break;

                /* ATCA ECDSA VERIFY */
		case ZF_SYSCALL_USER + 12: {
                    uint8_t *sig;
                    zf_addr sig_addr = zf_pop();
                    zf_cell siglen = get_crypto_pointer(&sig, sig_addr);

                    zf_cell pub_key_id = zf_pop();

                    uint8_t *digest;
                    zf_addr dig_addr = zf_pop();
                    zf_cell diglen = get_crypto_pointer(&digest, dig_addr);

                    int8_t pass = 0;

                    if (siglen != 64)
                    	fprintf(stderr, "sig buf not 64 bytes.");
                    else if (diglen != 32)
                    	fprintf(stderr, "digest buf not 32 bytes.");
                    else
                    {
                        status = atcab_verify_stored(digest, sig, pub_key_id, (bool *)&pass);
                        if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_verify_extern() failed: %02x\r\n", status);
			else
			{
			    if (pass)
			        zf_push(0);
			    else
				zf_push(-1);
			}
                    } }
	            break;

                /* ATCA GET PUB KEY */
		case ZF_SYSCALL_USER + 13: {
		    uint8_t *pubkey;
                    zf_addr pk_addr = zf_pop();
		    uint8_t len = get_crypto_pointer(&pubkey, pk_addr);
                    if (len != 64)
                        fprintf(stderr, "pubkey buf not 64 bytes.");
		    else
		    {
                    	status = atcab_get_pubkey(zf_pop(), pubkey);
                    	if (status != ATCA_SUCCESS)
                    	    fprintf(stderr, "atcab_get_pubkey() failed: %02x\r\n", status);
		    } }
	            break;

                /* ATCA SET PUB KEY */
		case ZF_SYSCALL_USER + 14: {
		    uint8_t *pubkey;
                    zf_addr pk_addr = zf_pop();
		    uint8_t len = get_crypto_pointer(&pubkey, pk_addr);
                    if (len != 64)
                        fprintf(stderr, "pubkey buf not 64 bytes.");
		    else
		    {
                    	status = atcab_write_pubkey(zf_pop(), pubkey);
                    	if (status != ATCA_SUCCESS)
                    	    fprintf(stderr, "atcab_write_pubkey() failed: %02x\r\n", status);
		    } }
	            break;

                /* ATCA ECDH */
		case ZF_SYSCALL_USER + 15: {
                    uint8_t *sharsec;
                    zf_addr shsc_addr = zf_pop();
                    zf_cell shsclen = get_crypto_pointer(&sharsec, shsc_addr);

                    zf_cell pri_key_id = zf_pop();

		    uint8_t *pubkey;
                    zf_addr pk_addr = zf_pop();
		    uint8_t pklen = get_crypto_pointer(&pubkey, pk_addr);

                    if (pklen != 64)
                    	fprintf(stderr, "pubkey buf not 64 bytes.");
                    else if (shsclen != 32)
                    	fprintf(stderr, "sharsec buf not 32 bytes.");
                    else
                    {
                        status = atcab_ecdh(pri_key_id, pubkey, sharsec);
                        if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_ecdh() failed: %02x\r\n", status);
                    } }
	            break;

                /* GET STRONGFORTH STATUS */
		case ZF_SYSCALL_USER + 16:
		    zf_push(strongheld_status_get());
	            break;

                /* ATCA GET SERIAL */
		case ZF_SYSCALL_USER + 17: {
                    uint8_t *serial;
                    zf_addr ser_addr = zf_pop();
                    zf_cell serlen = get_crypto_pointer(&serial, ser_addr);

                    if (serlen != 9)
                    	fprintf(stderr, "serial buf not 9 bytes.");
                    else
                    {
                        status = atcab_read_serial_number(serial);
                        if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_read_serial_number() failed: %02x\r\n", status);
                    } }
	            break;

                /* KEY ROTATION PREP */
		case ZF_SYSCALL_USER + 18: {
		    /* returning the old key */
		    uint8_t *pubkey;
                    zf_addr pk_addr = zf_pop();
		    uint8_t pklen = get_crypto_pointer(&pubkey, pk_addr);

		    /* get the serial number */
                    uint8_t *serial;
                    zf_addr ser_addr = zf_pop();
                    zf_cell serlen = get_crypto_pointer(&serial, ser_addr);

		    /* get seed value for nonce */
                    uint8_t *digest;
                    zf_addr dig_addr = zf_pop();
                    zf_cell diglen = get_crypto_pointer(&digest, dig_addr);

		    uint16_t slot_config = 0;
		    uint16_t key_config = 0;

		    /* SET VALUE FOR TESTING */
	   	    uint8_t validated_nonce[] = {
0xD9, 0x27, 0x4A, 0xBA, 0xD4, 0xCD, 0xC1, 0xCA, 0xF4, 0x5A, 0x0E, 0x93, 0x3C, 0x3E, 0x58, 0x65,
0x60, 0xC1, 0xA5, 0xA0, 0xF3, 0x68, 0xA2, 0xC7, 0x1C, 0xA3, 0xCB, 0x6B, 0x92, 0x5B, 0x9E, 0x95,
};
                    if (serlen != 9)
                    	fprintf(stderr, "serial buf not 9 bytes.");
		    else if (diglen != 32)
                    	fprintf(stderr, "serial buf not 32 bytes.");
		    else if (pklen != 64)
                    	fprintf(stderr, "pubkey buf not 64 bytes.");
                    else
                    {
                        status = atcab_nonce(validated_nonce);
                        if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_nonce() failed: %02x\r\n", status);

			if (status == ATCA_SUCCESS)
			{
                        	status = atcab_read_pubkey(14, pubkey);
				if (status != ATCA_SUCCESS)
                            		fprintf(stderr, "atcab_read_pubkey() failed: %02x\r\n",
							status);
			}
			if (status == ATCA_SUCCESS)
			{
                        	status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1,
						48, (uint8_t*) &slot_config, 1);
                        	status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1,
						49, (uint8_t*) &slot_config + 1, 1);
                        	if (status != ATCA_SUCCESS)
                            		fprintf(stderr, "atcab_read_bytes_zone() failed: %02x\r\n",
							status);
			}
			if (status == ATCA_SUCCESS)
			{
                        	status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1,
						124, (uint8_t*) &key_config, 1);
                        	status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, -1,
						125, (uint8_t*) &key_config + 1, 1);
                        	if (status != ATCA_SUCCESS)
                            		fprintf(stderr, "atcab_read_bytes_zone() failed: %02x\r\n",
							status);
			}
			if (status == ATCA_SUCCESS)
			{
				zf_push(slot_config);
				zf_push(key_config);
			}
                    } }
	            break;

                /* KEY ROTATION */
		case ZF_SYSCALL_USER + 19: {
		    /* signature */
                    uint8_t *sig;
                    zf_addr sig_addr = zf_pop();
                    zf_cell siglen = get_crypto_pointer(&sig, sig_addr);

		    /* get genkey data */
                    uint8_t *gendata;
                    zf_addr gen_addr = zf_pop();
                    zf_cell genlen = get_crypto_pointer(&gendata, gen_addr);

		    /* get verifiaction data */
                    uint8_t *verdata;
                    zf_addr ver_addr = zf_pop();
                    zf_cell verlen = get_crypto_pointer(&verdata, ver_addr);

                    zf_cell validate = zf_pop();

		    bool is_verified = -1;

		    if (siglen != 64)
                    	fprintf(stderr, "sig buf not 64 bytes.");
		    else if (verlen != 19)
                    	fprintf(stderr, "verdata buf not 19 bytes.");
		    else if (genlen != 3)
                    	fprintf(stderr, "gendata buf not 3 bytes.");
                    else
                    {
			status = atcab_genkey_base(GENKEY_MODE_PUBKEY_DIGEST, 14, gendata, NULL);
			if (status != ATCA_SUCCESS)
                            fprintf(stderr, "atcab_genkey_base() failed: %02x\r\n", status);
			else
			{
				if (validate == 0)
					status = atcab_verify_validate(14,
							sig, verdata, &is_verified);
				else if (validate == -1)
					status = atcab_verify_invalidate(14,
							sig, verdata, &is_verified);
				else
					status = ATCA_GEN_FAIL;

				if (status != ATCA_SUCCESS)
                            		fprintf(stderr, "atcab_verify_(in)validate() failed: %02x\r\n", status);
				else
				{
					if (is_verified)
						zf_push(0);
					else
						zf_push(-1);
				}
			}
		    } }
	            break;

                /* READ PUBKEY SLOT */
		case ZF_SYSCALL_USER + 20: {
		    uint8_t *pubkey;
                    zf_addr pk_addr = zf_pop();
		    uint8_t pklen = get_crypto_pointer(&pubkey, pk_addr);

		    if (pklen != 64)
                    	fprintf(stderr, "pubkey buf not 64 bytes.");
		    else
		    {
		    	status = atcab_read_pubkey(zf_pop(), pubkey);
		    	if (status != ATCA_SUCCESS)
                		fprintf(stderr, "atcab_read_pubkey() failed: %02x\r\n",
						status);
		    } }
	            break;

                /* TEST */
		case ZF_SYSCALL_USER + 21: {

		    uint8_t a = 1;
		    uint8_t b = 2;
		    uint16_t c = a | b << 8;
		    printf("\n%u\n", c);
		    uint16_t d;
		    memset((uint8_t*)&d, a, 1);
		    memset((uint8_t*)&d + 1, b, 1);
		    printf("\n%u\n", d);

		    uint8_t config[128];
		    uint16_t rotating_key_slot = 14;
        	    if ((status = atcab_read_config_zone(config)) != ATCA_SUCCESS)
			    break;
		    uint16_t slot_config = (config[20 + rotating_key_slot * 2]   | config[21 + rotating_key_slot * 2] << 8);
        	    uint16_t key_config = (config[96 + rotating_key_slot * 2] | config[97 + rotating_key_slot * 2] << 8);
		    printf("\n%u\n", slot_config);
		    printf("\n%u\n", key_config);

		    uint32_t valid;
		    status = atcab_read_zone(ATCA_ZONE_DATA, rotating_key_slot, 0, 0, (uint8_t*)&valid, 4);
		    if (status != ATCA_SUCCESS)
                    	fprintf(stderr, "atcab_verify_(in)validate() failed: %02x\r\n", status);
	            if (status == ATCA_SUCCESS)
		    	printf("\n%u\n", valid);
    		    uint8_t validated_signature[] = {
			  0x28, 0x4e, 0x92, 0xa8, 0xc7, 0x7d, 0x28, 0x8c, 0x4b, 0xec,
			  0x72, 0x35, 0x6a, 0x6f, 0xb3, 0xfa, 0xab, 0x6c, 0x8b, 0x7c,
			  0x31, 0xc4, 0x2f, 0xd4, 0xca, 0xe8, 0x8b, 0x9a, 0x0b, 0x07, 0x33, 0x4b };
    		    base32_emit(validated_signature, 32);
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

