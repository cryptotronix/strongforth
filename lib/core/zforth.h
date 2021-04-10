#ifndef zforth_h
#define zforth_h

#include "strongforth_conf.h"

/* Abort reasons */

typedef enum {
	ZF_OK,
	ZF_ABORT_INTERNAL_ERROR,
	ZF_ABORT_OUTSIDE_MEM,
	ZF_ABORT_DSTACK_UNDERRUN,
	ZF_ABORT_DSTACK_OVERRUN,
	ZF_ABORT_RSTACK_UNDERRUN,
	ZF_ABORT_RSTACK_OVERRUN,
	ZF_ABORT_NOT_A_WORD,
	ZF_ABORT_COMPILE_ONLY_WORD,
	ZF_ABORT_INVALID_SIZE,
	ZF_ABORT_DIVISION_BY_ZERO,
	ZF_ABORT_DICT_WRITE_DISABLED,
	ZF_ABORT_NOT_A_REGISTER
} zf_result;

typedef enum {
	ZF_MEM_SIZE_VAR,
	ZF_MEM_SIZE_CELL,
	ZF_MEM_SIZE_U8,
	ZF_MEM_SIZE_U16,
	ZF_MEM_SIZE_U32,
	ZF_MEM_SIZE_S8,
	ZF_MEM_SIZE_S16,
	ZF_MEM_SIZE_S32
} zf_mem_size;

typedef enum {
	ZF_INPUT_INTERPRET,
	ZF_INPUT_PASS_CHAR,
	ZF_INPUT_PASS_WORD
} zf_input_state;

typedef enum {
	ZF_SYSCALL_EMIT,
	ZF_SYSCALL_PRINT,
	ZF_SYSCALL_TELL,
	ZF_SYSCALL_USER = 128
} zf_syscall_id;

#if ZF_ENABLE_CONST_DICTIONARY
/* Registers */
typedef struct stf_register {
	uint8_t cipher[64];
	uint8_t epk[64];
	uint8_t pubkey[64];
	uint8_t sig[64];
	uint8_t digest[32];
	uint8_t dolink[32];
	uint8_t nonce[32];
	uint8_t prikey[32];
	uint8_t rand[32];
	uint8_t sharesec[32];
	uint8_t symkey[32];
	uint8_t uplink[32];
	uint8_t msg[28];
	uint8_t seed[20];
	uint8_t ver_data[19];
	uint8_t serial[9];
	uint8_t count[4];
	uint8_t domsgid[4];
	uint8_t upmsgid[4];
	uint8_t gen_data[3];
} stf_register_t;

/* Manually numbered for easier slicing */
/* Register Names */
typedef enum {
	STF_REG_PUBKEY = 0,
	STF_REG_PRIKEY = 1,
	STF_REG_SIG = 2,
	STF_REG_RAND = 3,
	STF_REG_DIGEST = 4,
	STF_REG_SHARESEC = 5,
	STF_REG_SERIAL = 6,
	STF_REG_VER_DATA = 7,
	STF_REG_GEN_DATA = 8,
	STF_REG_SEED = 9,
	STF_REG_COUNT = 10,
	STF_REG_CIPHER = 11,
	STF_REG_MSG = 12,
	STF_REG_SYMKEY = 13,
	STF_REG_EPK = 14,
	STF_REG_NONCE = 15,
	STF_REG_UPLINK = 16,
	STF_REG_DOLINK = 17,
	STF_REG_UPMSGID = 18,
	STF_REG_DOMSGID = 19
} stf_register_id;
#endif


/* ZForth API functions */


void zf_init(int trace);
void zf_bootstrap(void);
#if ZF_ENABLE_CONST_DICTIONARY
const void *zf_dump(size_t *len);
#else
void *zf_dump(size_t *len);
#endif
zf_result zf_eval(const char *buf);
void zf_abort(zf_result reason);

void zf_push(zf_cell v);
zf_cell zf_pop(void);
zf_cell zf_pick(zf_addr n);

void dict_get_bytes(zf_addr addr, void *buf, size_t len);
zf_addr dict_put_bytes(zf_addr addr, const void *buf, size_t len);
#if !ZF_ENABLE_CONST_DICTIONARY
uint8_t *dict_get_pointer(zf_addr addr, size_t len);
#endif

/* Host provides these functions */

zf_input_state zf_host_sys(zf_syscall_id id, const char *last_word);
void zf_host_trace(const char *fmt, va_list va);
zf_cell zf_host_parse_num(const char *buf, uint8_t *b32);

#endif
