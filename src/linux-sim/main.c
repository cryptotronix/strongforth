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

#include <cryptoauthlib/host/atca_host.h>

#ifdef USE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <crypto/hashes/sha2_routines.h>

#include "hydrogen.h"

#include "zforth.h"
#include "base32.h"
#include "uECC.h"


#define HYDRO_CONTEXT "strongfo"
#define HYDRO_MLEN (28)
#define HYDRO_CLEN (HYDRO_MLEN + hydro_secretbox_HEADERBYTES)

zf_addr B32_INPUT = 0;

sw_sha256_ctx g_sha256_ctx;

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
            printf(" ERROR");
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

    /*  SHA256 INIT */
    case ZF_SYSCALL_USER + 40: {
        sw_sha256_init(&g_sha256_ctx);
    }
        break;

        /*  SHA256 UPDATE */
    case ZF_SYSCALL_USER + 41: {
        uint8_t *p;
        int p_len = get_crypto_pointer(&p, zf_pop());

        sw_sha256_update(&g_sha256_ctx, p, p_len);

    }
        break;

        /*  SHA256 FINAL */
    case ZF_SYSCALL_USER + 42: {

        uint8_t *p;
        int p_len = get_crypto_pointer(&p, zf_pop());
        assert (32 == p_len);

        sw_sha256_final(&g_sha256_ctx, p);


        sw_sha256_update(&g_sha256_ctx, p, p_len);

    }
        break;
    case ZF_SYSCALL_USER + 43: {

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
        break;

    case ZF_SYSCALL_USER + 44: {

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
        break;

    /* SERVER'S KEY ROTATION PREP */
    case ZF_SYSCALL_USER + 45: {
        uint8_t *digest;
        int digest_len = get_crypto_pointer(&digest, zf_pop());

        uint8_t *verify_other_data;
        int verdata_len = get_crypto_pointer(&verify_other_data, zf_pop());

        uint8_t *gen_key_other_data;
        int gendata_len = get_crypto_pointer(&gen_key_other_data, zf_pop());

	uint16_t key_bit = zf_pop();
	uint16_t slot_bit = zf_pop();

        uint8_t *serial;
        int serial_len = get_crypto_pointer(&serial, zf_pop());

        uint8_t *pubkey;
        int pubkey_len = get_crypto_pointer(&pubkey, zf_pop());

        uint8_t *random;
        int rand_len = get_crypto_pointer(&random, zf_pop());

        uint8_t *seed;
        int seed_len = get_crypto_pointer(&seed, zf_pop());

	zf_cell validate = zf_pop();

	atca_gen_key_in_out_t gen_key_params;
	atca_sign_internal_in_out_t sign_params;
    	uint8_t validation_msg[55];
        atca_temp_key_t temp_key;
	atca_nonce_in_out_t nonce_params;
        ATCA_STATUS status = ATCA_GEN_FAIL;

        assert(digest_len == 32);
        assert(verdata_len == 19);
        assert(gendata_len == 3);
        assert(serial_len == 9);
        assert(pubkey_len == 64);
        assert(rand_len == 32);
        assert(seed_len == 20);

	if (validate == 0)
		validate = 1;
	else if (validate == -1)
		validate = 0;

        memset(&temp_key, 0, sizeof(temp_key));
        memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = seed;
        nonce_params.rand_out = random;
        nonce_params.temp_key = &temp_key;

        status = atcah_nonce(&nonce_params);
        if (status != ATCA_SUCCESS)
		fprintf(stderr, "atcah_nonce() failed: %02x\r\n", status);

	if (status == ATCA_SUCCESS)
	{
		memset(gen_key_other_data, 0, 3);
        	gen_key_params.mode = GENKEY_MODE_PUBKEY_DIGEST;
        	gen_key_params.key_id = 14;
        	gen_key_params.public_key = pubkey;
        	gen_key_params.public_key_size = pubkey_len;
        	gen_key_params.other_data = gen_key_other_data;
        	gen_key_params.sn = serial;
        	gen_key_params.temp_key = &temp_key;

        	status = atcah_gen_key_msg(&gen_key_params);
        	if (status != ATCA_SUCCESS)
			fprintf(stderr, "atcah_gen_key_msg() failed: %02x\r\n", status);
	}
	if (status == ATCA_SUCCESS)
	{
        	memset(&sign_params, 0, sizeof(sign_params));
       		sign_params.sn = serial;
        	sign_params.verify_other_data = verify_other_data;
        	sign_params.key_id = 13;
        	sign_params.slot_config = key_bit;
        	sign_params.key_config = slot_bit;
        	sign_params.for_invalidate = !validate;
        	sign_params.message = validation_msg;
        	sign_params.digest = digest;
        	sign_params.temp_key = &temp_key;

        	status = atcah_sign_internal_msg(ATECC608A, &sign_params);
        	if (status != ATCA_SUCCESS)
			fprintf(stderr, "atcah_sign_internal_msg() failed: %02x\r\n", status);
	}
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

    if (hydro_init() != 0)
    {
        return -1;
    }

    sw_sha256_init(&g_sha256_ctx);
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
