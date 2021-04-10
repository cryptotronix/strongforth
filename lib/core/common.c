#include "common.h"

#if ZF_ENABLE_CONST_DICTIONARY
uint8_t get_register(uint8_t **buf, stf_register_id reg_id)
{
	uint8_t len = 0;
	switch((int)reg_id)
    	{
		case STF_REG_PUBKEY:
			*buf = STF_REGISTERS.pubkey;
			len = sizeof(STF_REGISTERS.pubkey);
			break;

		case STF_REG_PRIKEY:
			*buf = STF_REGISTERS.prikey;
			len = sizeof(STF_REGISTERS.prikey);
			break;

		case STF_REG_SIG:
			*buf = STF_REGISTERS.sig;
			len = sizeof(STF_REGISTERS.sig);
			break;

		case STF_REG_RAND:
			*buf = STF_REGISTERS.rand;
			len = sizeof(STF_REGISTERS.rand);
			break;

		case STF_REG_DIGEST:
			*buf = STF_REGISTERS.digest;
			len = sizeof(STF_REGISTERS.digest);
			break;

		case STF_REG_SHARESEC:
			*buf = STF_REGISTERS.sharesec;
			len = sizeof(STF_REGISTERS.sharesec);
			break;

		case STF_REG_SERIAL:
			*buf = STF_REGISTERS.serial;
			len = sizeof(STF_REGISTERS.serial);
			break;

		case STF_REG_VER_DATA:
			*buf = STF_REGISTERS.ver_data;
			len = sizeof(STF_REGISTERS.ver_data);
			break;

		case STF_REG_GEN_DATA:
			*buf = STF_REGISTERS.gen_data;
			len = sizeof(STF_REGISTERS.gen_data);
			break;

		case STF_REG_SEED:
			*buf = STF_REGISTERS.seed;
			len = sizeof(STF_REGISTERS.seed);
			break;

		case STF_REG_COUNT:
			*buf = STF_REGISTERS.count;
			len = sizeof(STF_REGISTERS.count);
			break;

		case STF_REG_CIPHER:
			*buf = STF_REGISTERS.cipher;
			len = sizeof(STF_REGISTERS.cipher);
			break;

		case STF_REG_MSG:
			*buf = STF_REGISTERS.msg;
			len = sizeof(STF_REGISTERS.msg);
			break;

		case STF_REG_SYMKEY:
			*buf = STF_REGISTERS.symkey;
			len = sizeof(STF_REGISTERS.symkey);
			break;

		case STF_REG_EPK:
			*buf = STF_REGISTERS.epk;
			len = sizeof(STF_REGISTERS.epk);
			break;

		case STF_REG_NONCE:
			*buf = STF_REGISTERS.nonce;
			len = sizeof(STF_REGISTERS.nonce);
			break;

		case STF_REG_UPLINK:
			*buf = STF_REGISTERS.uplink;
			len = sizeof(STF_REGISTERS.uplink);
			break;

		case STF_REG_DOLINK:
			*buf = STF_REGISTERS.dolink;
			len = sizeof(STF_REGISTERS.dolink);
			break;

		case STF_REG_UPMSGID:
			*buf = STF_REGISTERS.upmsgid;
			len = sizeof(STF_REGISTERS.upmsgid);
			break;

		case STF_REG_DOMSGID:
			*buf = STF_REGISTERS.domsgid;
			len = sizeof(STF_REGISTERS.domsgid);
			break;

		default:
			*buf = NULL;
			len = 0;
			zf_abort(ZF_ABORT_NOT_A_REGISTER);
	}

	return len;
}
#else
uint8_t get_register(uint8_t **buf, zf_addr addr)
{
    uint8_t len = 0;
    /* gets the length */
    dict_get_bytes(addr, &len, 1);
    /* get the actual data */
    *buf = dict_get_pointer(addr + 1, len);
    return len;
}
#endif
