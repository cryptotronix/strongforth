#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cryptoauthlib/host/atca_host.h>

#include "strongforth.h"
#include "common.h"
#include "server.h"
#include "uECC.h"

#define STF_SERVER_SYSCALL_GETRAND ZF_SYSCALL_USER + 9
#define STF_SERVER_SYSCALL_SIGN ZF_SYSCALL_USER + 10
#define STF_SERVER_SYSCALL_VERIFY ZF_SYSCALL_USER + 11
#define STF_SERVER_SYSCALL_ECDH ZF_SYSCALL_USER + 12
#define STF_DEVICE_SYSCALL_GENKEY ZF_SYSCALL_USER + 14
#define STF_SERVER_SYSCALL_SHA256_INIT ZF_SYSCALL_USER + 40
#define STF_SERVER_SYSCALL_SHA256_UPDATE ZF_SYSCALL_USER + 41
#define STF_SERVER_SYSCALL_SHA256_FINALIZE ZF_SYSCALL_USER + 42
#define STF_SERVER_SYSCALL_ROT2 ZF_SYSCALL_USER + 43

sw_sha256_ctx g_sha256_ctx;

static inline void stf_server_get_random(void)
{
        uint8_t *r;
        int b32len = get_crypto_pointer(&r, zf_pop());
        assert(32 == b32len);
        int rd = open("/dev/urandom", O_RDONLY);
        assert (rd > 0);

        ssize_t result = read(rd, r, 32);
        assert (result >= 0);
}

static inline void stf_server_do_ecdsa_sign(void)
{
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

static inline void stf_server_do_ecdsa_verify(void)
{
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

static inline void stf_server_do_ecdh(void)
{
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

static inline void stf_server_do_genkey(void)
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

static inline void stf_server_key_rotation_intermediate(void)
{
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
	{
		fprintf(stderr, "atcah_nonce() failed: %02x\r\n", status);
		return;
	}

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
	{
		fprintf(stderr, "atcah_gen_key_msg() failed: %02x\r\n", status);
		return;
	}

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
	{
		fprintf(stderr, "atcah_sign_internal_msg() failed: %02x\r\n", status);
		return;
	}
}

void stf_server_sys(zf_syscall_id id, const char *input)
{
	switch((int)id)
	{
		case STF_SERVER_SYSCALL_GETRAND:
			stf_server_get_random();
			break;

		case STF_SERVER_SYSCALL_SIGN:
			stf_server_do_ecdsa_sign();
			break;

		case STF_SERVER_SYSCALL_VERIFY:
			stf_server_do_ecdsa_verify();
			break;

		case STF_SERVER_SYSCALL_ECDH:
			stf_server_do_ecdh();
			break;

		case STF_DEVICE_SYSCALL_GENKEY:
			stf_server_do_genkey();
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

		case STF_SERVER_SYSCALL_ROT2:
			stf_server_key_rotation_intermediate();
			break;

    	    	default:
    	    		printf("unhandled syscall %d\n", id);
    	    		break;
    }
}
