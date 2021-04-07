#include <atmel_start.h>
#include "cryptoauthlib.h"
#include "strongforth.c"

#define BLE_UART_RX_BUFFER_SIZE 256

static uint8_t rxbuf[BLE_UART_RX_BUFFER_SIZE] = {0};
static uint8_t rxidx = 0;

static bool stream_open = false;

static void read_ble_status()
{
    // using separate buffer from main rxbuf in case
    // we receive a status message in the middle of
    // receiving other data
    uint8_t statusbuf[BLE_UART_RX_BUFFER_SIZE] = {0};
    uint8_t i = 0;
    uint8_t c = 0;

    statusbuf[i++] = '%';

    do
    {
        c = BLE_UART_read();
        if (i < (BLE_UART_RX_BUFFER_SIZE - 1))
        {
            statusbuf[i++] = c;
        }
    } while (c != '%');

    statusbuf[i] = '\0';
    printf("ble status: %s\n", statusbuf);

    if(0 == strcmp("%DISCONNECT%", (char *)statusbuf))
    {
        stream_open = false;
        LED0_set_level(false);
    }
    else if (0 == strcmp("%STREAM_OPEN%", (char *)statusbuf))
    {
        stream_open = true;
        LED0_set_level(true);
    }
}

int main(void)
{
    /* Initializes MCU, drivers and middleware */
    atmel_start_init();

    printf("atmel_start_init done\n");

    ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
    cfg.atcai2c.baud = 100000;
    cfg.atcai2c.bus = 1;
    cfg.atcai2c.slave_address = 0x6C;

    stf_init(NULL, &cfg);

    printf("stf_init done \n");

    uint8_t sernum[9] = {0};

    ATCA_STATUS balls = atcab_read_serial_number(sernum);
    if (ATCA_SUCCESS != balls)
    {
        printf("could not get serial number, check atca cfg!\n");
    }
    else
    {
        printf("608 serial: ");
        for (uint8_t i = 0; i < sizeof(sernum); i++)
        {
            printf("%02x", sernum[i]);
        }
        printf("\n");
    }

    printf("releasing RN4870 from reset\n");

    BLE_RESET_set_level(true);

    while (1)
    {
        uint8_t c = BLE_UART_read();

        if (c == '%')
        {
            read_ble_status();
        }
        else if (stream_open)
        {
            if (c == '\r' || c == '\n')
            {
                 // process stf message
                rxbuf[rxidx++] = '\n';
                rxbuf[rxidx] = '\0';
                printf("stf_eval: %s", rxbuf);

                stf_eval_resp_t resp = stf_eval((const char *)rxbuf);
                char *respStr = stf_get_retbuf();
                if (resp.rc != 0 || resp.stf_status != 0)
                {
                    printf("stf_eval error!\n");
                    printf("rc: %lu\n", resp.rc);
                    printf("stf_status: %lu\n", resp.stf_status);
                }

                printf("response: %s\n", respStr);

                for (int i = 0; i < strlen(respStr); i++)
                {
                    BLE_UART_write(respStr[i]);
                }

                rxidx = 0;
                memset(rxbuf, 0, sizeof(rxbuf));
            }
            else
            {
                // check for overflow, we always need /0 byte at the end so check
                // for one less than buffer size
                if (rxidx >= (BLE_UART_RX_BUFFER_SIZE - 1))
                {
                    printf("ble rxbuf overflow! dumping extra chars until we get a newline\n");
                }
                else
                {
                    rxbuf[rxidx++] = c;
                }
            }
        }
    }
}
