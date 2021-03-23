/* 
 * File:   main.c
 * Author: chris
 *
 * Created on March 12, 2021, 3:15 PM
 */

#define UART_BAUD_RATE(BAUD_RATE) ((float)(F_CPU * 64 / (16 * (float)BAUD_RATE)) + 0.5)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <avr/io.h>
#include <math.h>
#include "protected_io.h"

#include "zforth.h"
#include "base32.h"
#include "cryptoauthlib.h"
#include "hydrogen.h"

zf_addr B32_INPUT = 0;

ATCAIfaceCfg cfg = {
    .iface_type                  = ATCA_I2C_IFACE,
    .devtype                     = ATECC608A,
    {
        .atcai2c.baud = 100000,
        .atcai2c.bus = 0,
        .atcai2c.slave_address = 0x6C,
    }
};

#define UNUSED(x) (void)(x)

static void uart_init(uint16_t baudrate);
static int uart_tx(char c, FILE *f);
static int uart_rx(FILE *);
static FILE f = FDEV_SETUP_STREAM(uart_tx, uart_rx, _FDEV_SETUP_RW);

#define CONTEXT "Strongforth"
#define MESSAGE "Test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (hydro_secretbox_HEADERBYTES + MESSAGE_LEN)

static uint8_t secret_key[hydro_secretbox_KEYBYTES] = {0};
static uint8_t ciphertext[CIPHERTEXT_LEN] = {0};

static inline void ccp_write_io(void *addr, uint8_t value)
{
	protected_write_io(addr, CCP_IOREG_gc, value);
}

void CLKCTRL_Initialize(void)
{
    //RUNSTDBY disabled; 
    ccp_write_io((void*)&(CLKCTRL.OSC32KCTRLA),0x00);

    //CSUT 1K; SEL disabled; RUNSTDBY disabled; ENABLE disabled; 
    ccp_write_io((void*)&(CLKCTRL.XOSC32KCTRLA),0x00);

    //RUNSTDBY disabled; 
    ccp_write_io((void*)&(CLKCTRL.OSC20MCTRLA),0x00);

    //PDIV 6X; PEN disabled; 
    ccp_write_io((void*)&(CLKCTRL.MCLKCTRLB),0x10);

    //CLKOUT disabled; CLKSEL OSC20M; 
    ccp_write_io((void*)&(CLKCTRL.MCLKCTRLA),0x00);

    //LOCKEN disabled; 
    ccp_write_io((void*)&(CLKCTRL.MCLKLOCK),0x00);
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

//void include(const char *fname)
//{
//	char buf[256];
//
//	FILE *f = fopen(fname, "rb");
//	int line = 1;
//	if(f) {
//		while(fgets(buf, sizeof(buf), f)) {
//			do_eval(fname, line++, buf);
//		}
//		fclose(f);
//	} else {
//		fprintf(stderr, "error opening file '%s': %s\n", fname, strerror(errno));
//	}
//}


/*
 * Save dictionary
 */

//static void save(const char *fname)
//{
//	size_t len;
//	void *p = zf_dump(&len);
//	FILE *f = fopen(fname, "wb");
//	if(f) {
//		fwrite(p, 1, len, f);
//		fclose(f);
//	}
//}


/*
 * Load dictionary
 */

//static void load(const char *fname)
//{
//	size_t len;
//	void *p = zf_dump(&len);
//	FILE *f = fopen(fname, "rb");
//	if(f) {
//		fread(p, 1, len, f);
//		fclose(f);
//	} else {
//		perror("read");
//	}
//}


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
//			if(input == NULL) {
//				return ZF_INPUT_PASS_WORD;
//			}
//			include(input);
			break;

		case ZF_SYSCALL_USER + 3:
			//save("zforth.save");
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
                    status = atcab_init(&cfg);
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
	        int r = sscanf(buf, "%d", (int *)&v);
	        if(r == 0) {
		        zf_abort(ZF_ABORT_NOT_A_WORD);
	        }
        }
	return v;
}


void uart_init(uint16_t baudrate)
{
    PORTA.DIR &= ~PIN1_bm;
    PORTA.DIR |= PIN0_bm;
    
    USART0.BAUD = baudrate;
    
    USART0.CTRLB |= USART_RXEN_bm | USART_TXEN_bm;
}


static int uart_tx(char c, FILE *f)
{
    UNUSED(f);
    
    while (!(USART0.STATUS & USART_DREIF_bm));
    
    USART0.TXDATAL = c;
	
    return 0;
}


int uart_rx(FILE *f)
{
    UNUSED(f);
	
    while (!(USART0.STATUS & USART_RXCIF_bm));
	
    return USART0.RXDATAL;
}

int main(void)
{
    int line = 0;
    int trace = 0;
    
    CLKCTRL_Initialize();
    
	/* Setup stdin/stdout */
	uart_init(UART_BAUD_RATE(115200));
	stdout = stdin = stderr = &f;
    
    printf("Hello ZForth!\r\n");

    if (0 != hydro_init())
    {
        printf("Could not init libhydrogen!\r\n");
    }
    
    // test secretbox
    printf("Generating secretbox key...\r\n");
    hydro_secretbox_keygen(secret_key);
    printf("Key: ");
    for (int i = 0; i < hydro_secretbox_KEYBYTES; i++)
    {
        printf("%02x", secret_key[i]);
    }
    printf("\r\n");
    
    printf("Encrypting message: %s\r\n", MESSAGE);
    if (0 != hydro_secretbox_encrypt(ciphertext, MESSAGE, MESSAGE_LEN, 0, CONTEXT, secret_key))
    {
        printf("Could not hydro_secretbox_encrypt message!\r\n");
    }
    
    printf("Ciphertext: ");
    for (int i = 0; i < CIPHERTEXT_LEN; i++)
    {
        printf("%02x", ciphertext[i]);
    }
    printf("\r\n");
    
    printf("Decrypting...\r\n");
    char decrypted[MESSAGE_LEN] = {0};
    if (0 != hydro_secretbox_decrypt(decrypted, ciphertext, CIPHERTEXT_LEN, 0, CONTEXT, secret_key))
    {
        printf("Could not hydro_secretbox_decrypt ciphertext!\r\n");
    }
    printf("Decrypted: %s\r\n", decrypted);
    
	/* Initialize zforth */
	zf_init(trace);
	zf_bootstrap();

	/* Main loop: read words and eval */
    char buf[256] = {0};
    uint8_t i = 0;
    
	while (1)
    {
		int c = getchar();
        putchar(c);
        if (c == '\n' || c == '\r')
		{
            printf("\r\n");
            do_eval("stdin", ++line, buf);
        }
        else if (i < (sizeof(buf) - 1))
        {
            buf[i++] = c;
        }
        
        buf[i] = '\0';
	}
    
    return 0;
}
