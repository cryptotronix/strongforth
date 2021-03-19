/* 
 * File:   main.c
 * Author: chris
 *
 * Created on March 12, 2021, 3:15 PM
 */

#define UART3_BAUD_RATE(BAUD_RATE) ((float)(F_CPU * 64 / (16 * (float)BAUD_RATE)) + 0.5)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <avr/io.h>
#include "protected_io.h"

#include "zforth.h"

#include "cryptoauthlib.h"

#define UNUSED(x) (void)(x)

static void uart_init(uint16_t baudrate);
static int uart_tx(char c, FILE *f);
static int uart_rx(FILE *);
static FILE f = FDEV_SETUP_STREAM(uart_tx, uart_rx, _FDEV_SETUP_RW);

static char buf[32];

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

int main(void)
{
    uint8_t random[32] = {0};
    
    CLKCTRL_Initialize();
    
	/* Setup stdin/stdout */
	uart_init(UART3_BAUD_RATE(9600));
	stdout = stdin = &f;

    ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
    cfg.devtype = ATECC608A;
    cfg.atcai2c.baud = 100000;
    cfg.atcai2c.slave_address = 0x6C;

    ATCA_STATUS status = atcab_init(&cfg);
    if (ATCA_SUCCESS != status)
    {
        printf("failed to init cryptoauthlib: 0x%02x\r\n", status);
    }
    
    status = atcab_random(random);
    if (ATCA_SUCCESS != status)
    {
        printf("failed to get random: 0x%02x\r\n", status);
    }
    else
    {
        printf("random: ");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", random[i]);
        }
        printf("\r\n");
    }

	/* Initialize zforth */

	zf_init(1);
	zf_bootstrap();
	zf_eval(": . 1 sys ;");


	/* Main loop: read words and eval */

	uint8_t l = 0;

	for(;;) {
		int c = getchar();
		putchar(c);
		if(c == 10 || c == 13 || c == 32) {
			zf_result r = zf_eval(buf);
			if(r != ZF_OK) puts("A");
			l = 0;
		} else if(l < sizeof(buf)-1) {
			buf[l++] = c;
		}

		buf[l] = '\0';
	}

}


zf_input_state zf_host_sys(zf_syscall_id id, const char *input)
{
	char buf[16];

	switch((int)id) {

		case ZF_SYSCALL_EMIT:
			putchar((char)zf_pop());
			fflush(stdout);
			break;

		case ZF_SYSCALL_PRINT:
			itoa(zf_pop(), buf, 10);
			puts(buf);
			break;
	}

	return 0;
}


zf_cell zf_host_parse_num(const char *buf)
{
	char *end;
    zf_cell v = strtol(buf, &end, 0);
	
    if (*end != '\0')
    {
        zf_abort(ZF_ABORT_NOT_A_WORD);
    }
    
    return v;
}


void uart_init(uint16_t baudrate)
{
    PORTB.DIR &= ~PIN1_bm;
    PORTB.DIR |= PIN0_bm;
    
    USART3.BAUD = baudrate;
    
    USART3.CTRLB |= USART_RXEN_bm | USART_TXEN_bm;
}


static int uart_tx(char c, FILE *f)
{
    UNUSED(f);
    
    while (!(USART3.STATUS & USART_DREIF_bm));
    
    USART3.TXDATAL = c;
	
    return 0;
}


int uart_rx(FILE *f)
{
    UNUSED(f);
	
    while (!(USART3.STATUS & USART_RXCIF_bm));
	
    return USART3.RXDATAL;
}
