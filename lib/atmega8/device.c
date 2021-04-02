#include "strongforth.h"
#include "common.h"
#include "device.h"

#define STF_DEVICE_SYSCALL_GETRAND ZF_SYSCALL_USER + 9
#define STF_DEVICE_SYSCALL_SIGN ZF_SYSCALL_USER + 10
#define STF_DEVICE_SYSCALL_VERIFY ZF_SYSCALL_USER + 11
#define STF_DEVICE_SYSCALL_ECDH ZF_SYSCALL_USER + 12
#define STF_DEVICE_SYSCALL_GENKEY ZF_SYSCALL_USER + 13
#define STF_DEVICE_SYSCALL_GETCOUNT ZF_SYSCALL_USER + 14
#define STF_DEVICE_SYSCALL_INCCOUNT ZF_SYSCALL_USER + 15
#define STF_DEVICE_SYSCALL_GETPUB ZF_SYSCALL_USER + 16
#define STF_DEVICE_SYSCALL_SETPUB ZF_SYSCALL_USER + 17
#define STF_DEVICE_SYSCALL_GETSERIAL ZF_SYSCALL_USER + 18
#define STF_DEVICE_SYSCALL_ROT1 ZF_SYSCALL_USER + 19
#define STF_DEVICE_SYSCALL_ROT3 ZF_SYSCALL_USER + 20
#define STF_DEVICE_SYSCALL_READPUB ZF_SYSCALL_USER + 21

static inline void stf_device_get_random(void)
{
    zf_addr addr = zf_pop();
    ATCA_STATUS status = atcab_random(dict_get_pointer(addr + 1, ATCA_KEY_SIZE));
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "atcab_random() failed: %02x\r\n", status);
    }
}

static inline void stf_device_get_counter(void)
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

static inline void stf_device_get_counter_inc(void)
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

static inline void stf_device_do_ecdsa_sign(void)
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

static inline void stf_device_do_ecdsa_verify(void)
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

static inline void stf_device_get_pubkey(void)
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

static inline void stf_device_set_pubkey(void)
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

static inline void stf_device_do_ecdh(void)
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

static inline void stf_device_do_genkey(void)
{
	//TODO put a new privkey in slot one
}

static inline void stf_device_get_serial(void)
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

static inline void stf_device_prep_key_rotate(void)
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

static inline void stf_device_key_rotate(void)
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

static inline void stf_device_read_pubkey_slot(void)
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

void stf_device_sys(zf_syscall_id id, const char *input)
{
	switch((int)id)
	{
		case STF_DEVICE_SYSCALL_GETRAND:
			stf_device_get_random();
			break;

		case STF_DEVICE_SYSCALL_GETCOUNT:
			stf_device_get_counter();
			break;

		case STF_DEVICE_SYSCALL_INCCOUNT:
			stf_device_get_counter_inc();
			break;

		case STF_DEVICE_SYSCALL_SIGN:
			stf_device_do_ecdsa_sign();
			break;

		case STF_DEVICE_SYSCALL_VERIFY:
			stf_device_do_ecdsa_verify();
			break;

		case STF_DEVICE_SYSCALL_GETPUB:
			stf_device_get_pubkey();
			break;

		case STF_DEVICE_SYSCALL_SETPUB:
			stf_device_set_pubkey();
			break;

		case STF_DEVICE_SYSCALL_ECDH:
			stf_device_do_ecdh();
			break;

		case STF_DEVICE_SYSCALL_GENKEY:
			stf_device_do_genkey();
			break;

		case STF_DEVICE_SYSCALL_GETSERIAL:
			stf_device_get_serial();
			break;

		case STF_DEVICE_SYSCALL_ROT1:
			stf_device_prep_key_rotate();
			break;

		case STF_DEVICE_SYSCALL_ROT3:
			stf_device_key_rotate();
			break;

		case STF_DEVICE_SYSCALL_READPUB:
			stf_device_read_pubkey_slot();
			break;

    	    	default:
    	    		printf("unhandled syscall %d\n", id);
    	    		break;
    }
}
