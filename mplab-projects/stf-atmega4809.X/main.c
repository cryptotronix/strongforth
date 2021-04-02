#include <atmel_start.h>
#include "cryptoauthlib.h"
#include "strongforth.c"

int main(void)
{
	/* Initializes MCU, drivers and middleware */
	atmel_start_init();
    
    DBG_UART_enable();

    printf("atmel_start_init done\r\n");
    
    ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
    cfg.atcai2c.baud = 100000;
    cfg.atcai2c.bus = 1;
    cfg.atcai2c.slave_address = 0x6C;
    
    stf_init(NULL, &cfg);
    
    printf("stf_init done \r\n");

	/* Replace with your application code */
	while (1) {
	}
}
