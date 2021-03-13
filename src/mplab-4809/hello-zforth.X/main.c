/* 
 * File:   main.c
 * Author: chris
 *
 * Created on March 12, 2021, 3:15 PM
 */
#define F_CPU 3333333
#define UART3_BAUD_RATE(BAUD_RATE) ((float)(F_CPU * 64 / (16 * (float)BAUD_RATE)) + 0.5)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <avr/io.h>

#include "zforth.h"

#define UNUSED(x) (void)(x)

static void uart_init(uint16_t baudrate);
static int uart_tx(char c, FILE *f);
static int uart_rx(FILE *);
static FILE f = FDEV_SETUP_STREAM(uart_tx, uart_rx, _FDEV_SETUP_RW);

static char buf[32];

int main(void)
{
	/* Setup stdin/stdout */

	uart_init(UART3_BAUD_RATE(9600));
	stdout = stdin = &f;


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
