
#include "cryptoauthlib.h"
#include "hal/atca_hal.h"
#include "twi0_master.h"
#include <avr/io.h>

static uint8_t address = 0;

ATCA_STATUS _i2c_send(uint8_t *data, int length)
{
    while(!I2C0_Open(address)); // sit here until we get the bus..
    I2C0_SetBuffer(data, length);
    I2C0_SetAddressNackCallback(I2C0_SetRestartWriteCallback, NULL); //NACK polling?
    I2C0_MasterWrite();
    while(I2C0_BUSY == I2C0_Close()); // sit here until finished.
    
    return ATCA_SUCCESS;
}

ATCA_STATUS _i2c_receive(uint8_t *data, uint16_t length)
{
    while(!I2C0_Open(address)); // sit here until we get the bus..
    I2C0_SetBuffer(data, length);
    I2C0_MasterRead();
    while(I2C0_BUSY == I2C0_Close()); // sit here until finished.
    
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    I2C0_Initialize();
    
    address = cfg->atcai2c.slave_address >> 1;
    
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

    if (0xFF != word_address)
    {
        txdata[0] = word_address;
        txlength++;
    }

    return _i2c_send(txdata, txlength);
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCA_STATUS status = ATCA_COMM_FAIL;
    uint16_t read_length = 1;
    
    if (!cfg || (NULL == rxlength) || (NULL == rxdata))
    {
        return ATCA_BAD_PARAM;
    }
    
    if (*rxlength < 1)
    {
        return ATCA_SMALL_BUFFER;
    }
    
    do
    {
        // read first byte
        status = _i2c_receive(&rxdata[0], read_length);

        if (ATCA_SUCCESS != status)
        {
            break;
        }

        read_length = rxdata[0];

        if (read_length > *rxlength)
        {
            status = ATCA_SMALL_BUFFER;
            break;
        }

        if (read_length < 4)
        {
            status = ATCA_RX_FAIL;
            break;
        }
        
        status = _i2c_receive(&rxdata[1], read_length - 1);
        
    } while(0);
    
    
    *rxlength = read_length;
    return status;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    uint8_t data[4] = {0};
    uint16_t rxLen = 4;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCA_STATUS status = ATCA_WAKE_FAILED;
    
    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }
    
    int retries = cfg->rx_retries;
    
    while(!I2C0_Open(0x00)); // sit here until we get the bus..
    I2C0_SetBuffer(data, 0);
    I2C0_SetAddressNackCallback(I2C0_SetReturnStopCallback, NULL);
    I2C0_MasterWrite();
    while(I2C0_BUSY == I2C0_Close()); // sit here until finished.
    
    atca_delay_us(cfg->wake_delay);
    
    while (retries-- > 0 && status != ATCA_SUCCESS)
    {
        status = _i2c_receive(data, rxLen);
    }
    
    if (retries <= 0)
    {
        return ATCA_TOO_MANY_COMM_RETRIES;
    }
    
    if (status != ATCA_SUCCESS)
    {
        return status;
    }
    
    return hal_check_wake(data, rxLen);
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t data = 0x02;
    
    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }
    
    return _i2c_send(&data, 1);
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t data = 0x01;
    
    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }
    
    return _i2c_send(&data, 1);
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found)
{
    return ATCA_UNIMPLEMENTED;
}