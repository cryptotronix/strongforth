/**
 * \file
 *
 * \brief I2C master driver.
 *
 (c) 2020 Microchip Technology Inc. and its subsidiaries.

    Subject to your compliance with these terms,you may use this software and
    any derivatives exclusively with Microchip products.It is your responsibility
    to comply with third party license terms applicable to your use of third party
    software (including open source software) that may accompany Microchip software.

    THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
    EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
    WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
    PARTICULAR PURPOSE.

    IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
    INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
    WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
    BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
    FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
    ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
    THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 */

/**
 * \defgroup doc_driver_i2c_master I2C Master Driver
 * \ingroup doc_driver_i2c
 *
 * \section doc_driver_i2c_master_rev Revision History
 * - v0.0.0.1 Initial Commit
 *
 *@{
 */

#include <i2c_master.h>
#include <i2c_types.h>
#include <driver_init.h>
#include <util/delay.h>
#include <stdbool.h>
#include <stdlib.h>
// #include "timeout.h"  // TODO: Add timeout integration

/***************************************************************************/
// I2C STATES
typedef enum {
	I2C_IDLE = 0,
	I2C_SEND_ADR_READ,
	I2C_SEND_ADR_WRITE,
	I2C_TX,
	I2C_RX,
	I2C_TX_EMPTY,
	I2C_SEND_RESTART_READ,
	I2C_SEND_RESTART_WRITE,
	I2C_SEND_RESTART,
	I2C_SEND_STOP,
	I2C_RX_DO_ACK,
	I2C_TX_DO_ACK,
	I2C_RX_DO_NACK_STOP,
	I2C_RX_DO_NACK_RESTART,
	I2C_RESET,
	I2C_ADDRESS_NACK,
	I2C_BUS_COLLISION,
	I2C_BUS_ERROR
} i2c_fsm_states_t;

// I2C Event Callback List
typedef enum {
	i2c_dataComplete = 0,
	i2c_writeCollision,
	i2c_addressNACK,
	i2c_dataNACK,
	i2c_timeOut,
	i2c_NULL
} i2c_callback_index;

// I2C Status Structure
typedef struct {
	unsigned         busy : 1;
	unsigned         inUse : 1;
	unsigned         bufferFree : 1;
	unsigned         addressNACKCheck : 1;
	i2c_address_t    address;       /// The I2C Address
	uint8_t *        data_ptr;      /// pointer to a data buffer
	size_t           data_length;   /// Bytes in the data buffer
	uint16_t         timeout;       /// I2C Timeout Counter between I2C Events.
	uint16_t         timeout_value; /// Reload value for the timeouts
	i2c_fsm_states_t state;         /// Driver State
	i2c_error_t      error;
	/*if timeoutDriverEnabled
	timerStruct_t timeout;
	*/
	i2c_callback callbackTable[6];
	void *       callbackPayload[6]; ///  each callback can have a payload
} i2c_status_t;

typedef i2c_fsm_states_t(stateHandlerFunction)(void);

i2c_status_t ECC_I2C_status = {0};

static void             ECC_I2C_set_callback(i2c_callback_index idx, i2c_callback cb, void *p);
static i2c_operations_t ECC_I2C_return_stop(void *p);
static i2c_operations_t ECC_I2C_return_reset(void *p);
static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_ADR_READ(void);
static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_ADR_WRITE(void);
static void             ECC_I2C_master_isr(void);

/**
 * \brief In a polled implementation, call this function in a loop to execute the FSM
 *
 * \return Nothing
 */
inline void ECC_I2C_poller(void);

/*if timeoutDriverEnabled>
ABSOLUTETIME_t ${i2cMasterFunctions["timeoutHandler"]}(void *p);

// place this function someplace in a periodic interrupt
ABSOLUTETIME_t ${i2cMasterFunctions["timeoutHandler"]}(void *p)
{
    ${msspI2cFunctions["disableIRQ"]}();
    ${i2cMasterFunctions["status"]}.state = I2C_RESET; // Jump to the Timeout state
    ${msspI2cFunctions["enableIRQ"]}();
    ${msspI2cFunctions["setIRQ"]}(); // force an interrupt to handle the timeout
    return 0;
}
*/
/**
 * \brief Set callback to be called when all specifed data has been transferred.
 *
 * \param[in] cb Pointer to callback function
 * \param[in] p  Pointer to the callback function's parameters
 *
 * \return Nothing
 */
void ECC_I2C_set_data_complete_callback(i2c_callback cb, void *p)
{
	ECC_I2C_set_callback(i2c_dataComplete, cb, p);
}

/**
 * \brief Set callback to be called when there has been a bus collision and arbitration was lost.
 *
 * \param[in] cb Pointer to callback function
 * \param[in] p  Pointer to the callback function's parameters
 *
 * \return Nothing
 */
void ECC_I2C_set_write_collision_callback(i2c_callback cb, void *p)
{
	ECC_I2C_set_callback(i2c_writeCollision, cb, p);
}

/**
 * \brief Set callback to be called when the transmitted address was NACK'ed.
 *
 * \param[in] cb Pointer to callback function
 * \param[in] p  Pointer to the callback function's parameters
 *
 * \return Nothing
 */
void ECC_I2C_set_address_nack_callback(i2c_callback cb, void *p)
{
	ECC_I2C_set_callback(i2c_addressNACK, cb, p);
}

/**
 * \brief Set callback to be called when the transmitted data was NACK'ed.
 *
 * \param[in] cb Pointer to callback function
 * \param[in] p  Pointer to the callback function's parameters
 *
 * \return Nothing
 */
void ECC_I2C_set_data_nack_callback(i2c_callback cb, void *p)
{
	ECC_I2C_set_callback(i2c_dataNACK, cb, p);
}

/**
 * \brief Set callback to be called when there was a bus timeout.
 *
 * \param[in] cb Pointer to callback function
 * \param[in] p  Pointer to the callback function's parameters
 *
 * \return Nothing
 */
void ECC_I2C_set_timeout_callback(i2c_callback cb, void *p)
{
	ECC_I2C_set_callback(i2c_timeOut, cb, p);
}

/**
 * \brief Initialize I2C interface
 * If module is configured to disabled state, the clock to the I2C is disabled
 * if this is supported by the device's clock system.
 *
 * \return Initialization status.
 * \retval 0 the init was successful
 * \retval 1 the init was not successful
 */
void ECC_I2C_init()
{

	// TWI0.CTRLA = 0 << TWI_FMPEN_bp /* FM Plus Enable: disabled */
	//		 | TWI_SDAHOLD_OFF_gc /* SDA hold time off */
	//		 | TWI_SDASETUP_4CYC_gc; /* SDA setup time is 4 clock cycles */

	// TWI0.DBGCTRL = 0 << TWI_DBGRUN_bp; /* Debug Run: disabled */

	TWI0.MBAUD = (uint8_t)TWI0_BAUD(100000, 0); /* set MBAUD register */

	TWI0.MCTRLA = 1 << TWI_ENABLE_bp        /* Enable TWI Master: enabled */
	              | 0 << TWI_QCEN_bp        /* Quick Command Enable: disabled */
	              | 0 << TWI_RIEN_bp        /* Read Interrupt Enable: disabled */
	              | 0 << TWI_SMEN_bp        /* Smart Mode Enable: disabled */
	              | TWI_TIMEOUT_DISABLED_gc /* Bus Timeout Disabled */
	              | 0 << TWI_WIEN_bp;       /* Write Interrupt Enable: disabled */
}

/**
 * \brief Open the I2C for communication
 *
 * \param[in] address The slave address to use in the transfer
 *
 * \return Initialization status.
 * \retval I2C_NOERR The I2C open was successful
 * \retval I2C_BUSY  The I2C open failed because the interface is busy
 * \retval I2C_FAIL  The I2C open failed with an error
 */
i2c_error_t ECC_I2C_open(i2c_address_t address)
{
	i2c_error_t ret = I2C_BUSY;

	if (!ECC_I2C_status.inUse) {
		ECC_I2C_status.address          = address;
		ECC_I2C_status.busy             = 0;
		ECC_I2C_status.inUse            = 1;
		ECC_I2C_status.addressNACKCheck = 0;
		ECC_I2C_status.state            = I2C_RESET;
		ECC_I2C_status.timeout_value    = 500; // MCC should determine a reasonable starting value here.
		ECC_I2C_status.bufferFree       = 1;
		/*
		        <#if timeoutDriverEnabled>
		        ECC_I2C_status.timeout.callbackPtr = ${i2cMasterFunctions["timeoutHandler"]};
		        </#if>
		*/
		// set all the call backs to a default of sending stop
		ECC_I2C_status.callbackTable[i2c_dataComplete]     = ECC_I2C_return_stop;
		ECC_I2C_status.callbackPayload[i2c_dataComplete]   = NULL;
		ECC_I2C_status.callbackTable[i2c_writeCollision]   = ECC_I2C_return_stop;
		ECC_I2C_status.callbackPayload[i2c_writeCollision] = NULL;
		ECC_I2C_status.callbackTable[i2c_addressNACK]      = ECC_I2C_return_stop;
		ECC_I2C_status.callbackPayload[i2c_addressNACK]    = NULL;
		ECC_I2C_status.callbackTable[i2c_dataNACK]         = ECC_I2C_return_stop;
		ECC_I2C_status.callbackPayload[i2c_dataNACK]       = NULL;
		ECC_I2C_status.callbackTable[i2c_timeOut]          = ECC_I2C_return_reset;
		ECC_I2C_status.callbackPayload[i2c_timeOut]        = NULL;

		TWI0.MCTRLB |= TWI_FLUSH_bm;
		TWI0.MSTATUS |= TWI_BUSSTATE_IDLE_gc;
		// Reset module
		TWI0.MSTATUS |= (TWI_RIF_bm | TWI_WIF_bm);

		ret = I2C_NOERR;
	}
	return ret;
}

void ECC_I2C_set_address(i2c_address_t address)
{
	ECC_I2C_status.address = address;
}

/**
 * \brief Close the I2C interface
 *
 * \return Status of close operation.
 * \retval I2C_NOERR The I2C close was successful
 * \retval I2C_BUSY  The I2C close failed because the interface is busy
 * \retval I2C_FAIL  The I2C close failed with an error
 */
i2c_error_t ECC_I2C_close(void)
{
	i2c_error_t ret = I2C_BUSY;
	// Bus is in error state, reset I2C hardware and report error
	if (TWI0.MSTATUS & TWI_BUSERR_bm) {
		ECC_I2C_status.busy  = false;
		ECC_I2C_status.error = I2C_FAIL;
	}
	if (!ECC_I2C_status.busy) {
		ECC_I2C_status.inUse = 0;
		// close it down
		ECC_I2C_status.address = 0xff; // 8-bit address is invalid so this is FREE
		TWI0.MSTATUS |= (TWI_RIF_bm | TWI_WIF_bm);
		TWI0.MCTRLA &= ~(TWI_RIEN_bm | TWI_WIEN_bm);
		ret = ECC_I2C_status.error;
	}
	return ret;
}

/**
 * \brief Set timeout to be used for I2C operations. Uses the Timeout driver.
 *
 * \param[in] to Timeout in ticks
 *
 * \return Nothing
 */
void ECC_I2C_set_timeout(uint8_t to)
{
	TWI0.MCTRLA &= ~(TWI_RIEN_bm | TWI_WIEN_bm);
	ECC_I2C_status.timeout_value = to;
	TWI0.MCTRLA |= (TWI_RIEN_bm | TWI_WIEN_bm);
}

/**
 * \brief Set baud rate to be used for I2C operations.
 *
 * \param[in] baud to set the transfer speed
 *
 * \return Nothing
 */
void ECC_I2C_set_baud_rate(uint32_t baud)
{
	TWI0.MBAUD = (uint8_t)TWI0_BAUD(baud, 0); /* set MBAUD register */
}

/**
 * \brief Sets up the data buffer to use, and number of bytes to transfer
 *
 * \param[in] buffer Pointer to data buffer to use for read or write data
 * \param[in] bufferSize Number of bytes to read or write from slave
 *
 * \return Nothing
 */
void ECC_I2C_set_buffer(void *buffer, size_t bufferSize)
{
	if (ECC_I2C_status.bufferFree) {
		ECC_I2C_status.data_ptr    = buffer;
		ECC_I2C_status.data_length = bufferSize;
		ECC_I2C_status.bufferFree  = false;
	}
}

/**
 * \brief Start an operation on an opened I2C interface
 *
 * \param[in] read Set to true for read, false for write
 *
 * \return Status of operation
 * \retval I2C_NOERR The I2C open was successful
 * \retval I2C_BUSY  The I2C open failed because the interface is busy
 * \retval I2C_FAIL  The I2C open failed with an error
 */
i2c_error_t ECC_I2C_master_operation(bool read)
{
	i2c_error_t ret = I2C_BUSY;
	if (!ECC_I2C_status.busy) {
		ECC_I2C_status.busy = true;
		ret                 = I2C_NOERR;

		if (read) {
			ECC_I2C_status.state = I2C_SEND_ADR_READ;
		} else {
			ECC_I2C_status.state = I2C_SEND_ADR_WRITE;
		}
		ECC_I2C_master_isr();

		ECC_I2C_poller();
	}
	return ret;
}

/**
 * \brief Identical to ECC_I2C_master_operation(true);
 */
i2c_error_t ECC_I2C_master_read(void)
{
	return ECC_I2C_master_operation(true);
}

/**
 * \brief Identical to ECC_I2C_master_operation(false);
 */
i2c_error_t ECC_I2C_master_write(void)
{
	return ECC_I2C_master_operation(false);
}

/************************************************************************/
/* Helper Functions                                                     */
/************************************************************************/

inline void ECC_I2C_poller(void)
{
	while (ECC_I2C_status.busy) {
		_delay_ms(10);
		while (!(TWI0.MSTATUS & TWI_RIF_bm) && !(TWI0.MSTATUS & TWI_WIF_bm)) {
		};
		_delay_ms(10);
		ECC_I2C_master_isr();
	}
}

static i2c_fsm_states_t ECC_I2C_do_I2C_RESET(void)
{
	TWI0.MCTRLB |= TWI_FLUSH_bm;
	TWI0.MSTATUS |= TWI_BUSSTATE_IDLE_gc;
	ECC_I2C_status.busy  = false; // Bus Free
	ECC_I2C_status.error = I2C_NOERR;
	return I2C_RESET; // park the FSM on reset
}

static i2c_fsm_states_t ECC_I2C_do_I2C_IDLE(void)
{
	ECC_I2C_status.busy  = false; // Bus Free
	ECC_I2C_status.error = I2C_NOERR;
	return I2C_IDLE; // park the FSM on IDLE
}

static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_RESTART_READ(void)
{
	return ECC_I2C_do_I2C_SEND_ADR_READ();
}

static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_RESTART_WRITE(void)
{
	return ECC_I2C_do_I2C_SEND_ADR_WRITE();
}

static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_RESTART(void)
{
	return ECC_I2C_do_I2C_SEND_ADR_READ();
}

static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_STOP(void)
{
	TWI0.MCTRLB |= TWI_MCMD_STOP_gc;
	return ECC_I2C_do_I2C_IDLE();
}

// TODO: probably need 2 addressNACK's one from read and one from write.
//       the do NACK before RESTART or STOP is a special case that a new state simplifies.
static i2c_fsm_states_t ECC_I2C_do_I2C_DO_ADDRESS_NACK(void)
{
	ECC_I2C_status.addressNACKCheck = 0;
	ECC_I2C_status.error            = I2C_FAIL;
	switch (ECC_I2C_status.callbackTable[i2c_addressNACK](ECC_I2C_status.callbackPayload[i2c_addressNACK])) {
	case i2c_restart_read:
		return ECC_I2C_do_I2C_SEND_RESTART_READ();
	case i2c_restart_write:
		return ECC_I2C_do_I2C_SEND_RESTART_WRITE();
	default:
		return ECC_I2C_do_I2C_SEND_STOP();
	}
}

static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_ADR_READ(void)
{

	ECC_I2C_status.addressNACKCheck = 1;
	TWI0.MADDR                      = ECC_I2C_status.address << 1 | 1;
	return I2C_RX;
}

static i2c_fsm_states_t ECC_I2C_do_I2C_SEND_ADR_WRITE(void)
{

	ECC_I2C_status.addressNACKCheck = 1;
	TWI0.MADDR                      = ECC_I2C_status.address << 1;
	return I2C_TX;
}

static i2c_fsm_states_t ECC_I2C_do_I2C_RX_DO_ACK(void)
{
	TWI0.MCTRLB &= ~(1 << TWI_ACKACT_bp);
	return I2C_RX;
}

static i2c_fsm_states_t ECC_I2C_do_I2C_TX_DO_ACK(void)
{
	TWI0.MCTRLB &= ~(1 << TWI_ACKACT_bp);
	return I2C_TX;
}

static i2c_fsm_states_t ECC_I2C_do_I2C_DO_NACK_STOP(void)
{
	TWI0.MCTRLB |= TWI_ACKACT_NACK_gc;
	TWI0.MCTRLB |= TWI_MCMD_STOP_gc;
	return ECC_I2C_do_I2C_IDLE();
}

static i2c_fsm_states_t ECC_I2C_do_I2C_DO_NACK_RESTART(void)
{
	TWI0.MCTRLB |= TWI_ACKACT_NACK_gc;
	return I2C_SEND_RESTART;
}

static i2c_fsm_states_t ECC_I2C_do_I2C_TX(void)
{
	if ((TWI0.MSTATUS & TWI_RXACK_bm)) // Slave replied with NACK
	{
		switch (ECC_I2C_status.callbackTable[i2c_dataNACK](ECC_I2C_status.callbackPayload[i2c_dataNACK])) {
		case i2c_restart_read:
			return ECC_I2C_do_I2C_SEND_RESTART_READ();
		case i2c_restart_write:
			return ECC_I2C_do_I2C_SEND_RESTART_WRITE();
		default:
		case i2c_continue:
		case i2c_stop:
			return ECC_I2C_do_I2C_SEND_STOP();
		}
	} else {
		ECC_I2C_status.addressNACKCheck = 0;
		TWI0.MDATA                      = *ECC_I2C_status.data_ptr++;
		return (--ECC_I2C_status.data_length) ? I2C_TX : I2C_TX_EMPTY;
	}
}

static i2c_fsm_states_t ECC_I2C_do_I2C_RX(void)
{
	ECC_I2C_status.addressNACKCheck = 0;

	if (ECC_I2C_status.data_length == 1)
		TWI0.MCTRLB |= TWI_ACKACT_NACK_gc; // Next byte will be last to be received, setup NACK
	else
		TWI0.MCTRLB &= ~(1 << TWI_ACKACT_bp); // More bytes to receive, setup ACK

	if (--ECC_I2C_status.data_length) {
		*ECC_I2C_status.data_ptr = TWI0.MDATA;
		ECC_I2C_status.data_ptr++;
		TWI0.MCTRLB |= TWI_MCMD_RECVTRANS_gc;
		return I2C_RX;
	} else {
		*ECC_I2C_status.data_ptr = TWI0.MDATA;
		ECC_I2C_status.data_ptr++;
		ECC_I2C_status.bufferFree = true;
		switch (ECC_I2C_status.callbackTable[i2c_dataComplete](ECC_I2C_status.callbackPayload[i2c_dataComplete])) {
		case i2c_restart_write:
		case i2c_restart_read:
			return ECC_I2C_do_I2C_DO_NACK_RESTART();
		default:
		case i2c_continue:
		case i2c_stop:
			return ECC_I2C_do_I2C_DO_NACK_STOP();
		}
	}
}

static i2c_fsm_states_t ECC_I2C_do_I2C_TX_EMPTY(void)
{
	if ((TWI0.MSTATUS & TWI_RXACK_bm)) // Slave replied with NACK
	{
		switch (ECC_I2C_status.callbackTable[i2c_dataNACK](ECC_I2C_status.callbackPayload[i2c_dataNACK])) {
		case i2c_restart_read:
			return ECC_I2C_do_I2C_SEND_RESTART_READ();
		case i2c_restart_write:
			return ECC_I2C_do_I2C_SEND_RESTART_WRITE();
		default:
		case i2c_continue:
		case i2c_stop:
			return ECC_I2C_do_I2C_SEND_STOP();
		}
	} else {
		ECC_I2C_status.bufferFree = true;
		switch (ECC_I2C_status.callbackTable[i2c_dataComplete](ECC_I2C_status.callbackPayload[i2c_dataComplete])) {
		case i2c_restart_read:
			return ECC_I2C_do_I2C_SEND_RESTART_READ();
		case i2c_restart_write:
			return ECC_I2C_do_I2C_SEND_RESTART_WRITE();
		case i2c_continue:
			return ECC_I2C_do_I2C_TX();
		default:
		case i2c_stop:
			return ECC_I2C_do_I2C_SEND_STOP();
		}
	}
}

static i2c_fsm_states_t ECC_I2C_do_I2C_BUS_COLLISION(void)
{
	// Clear bus collision status flag
	TWI0.MSTATUS |= TWI_ARBLOST_bm;
	;
	ECC_I2C_status.error = I2C_FAIL;
	switch (ECC_I2C_status.callbackTable[i2c_writeCollision](ECC_I2C_status.callbackPayload[i2c_writeCollision])) {
	case i2c_restart_read:
		return ECC_I2C_do_I2C_SEND_RESTART_READ();
	case i2c_restart_write:
		return ECC_I2C_do_I2C_SEND_RESTART_WRITE();
	default:
		return ECC_I2C_do_I2C_RESET();
	}
}

static i2c_fsm_states_t ECC_I2C_do_I2C_BUS_ERROR(void)
{
	TWI0.MCTRLB |= TWI_FLUSH_bm;
	TWI0.MSTATUS |= TWI_BUSSTATE_IDLE_gc;
	ECC_I2C_status.busy  = false;
	ECC_I2C_status.error = I2C_FAIL;
	return I2C_RESET; // park the FSM on reset
}

stateHandlerFunction *ECC_I2C_fsmStateTable[] = {
    ECC_I2C_do_I2C_IDLE,               // I2C_IDLE
    ECC_I2C_do_I2C_SEND_ADR_READ,      // I2C_SEND_ADR_READ
    ECC_I2C_do_I2C_SEND_ADR_WRITE,     // I2C_SEND_ADR_WRITE
    ECC_I2C_do_I2C_TX,                 // I2C_TX
    ECC_I2C_do_I2C_RX,                 // I2C_RX
    ECC_I2C_do_I2C_TX_EMPTY,           // I2C_TX_EMPTY
    ECC_I2C_do_I2C_SEND_RESTART_READ,  // I2C_SEND_RESTART_READ
    ECC_I2C_do_I2C_SEND_RESTART_WRITE, // I2C_SEND_RESTART_WRITE
    ECC_I2C_do_I2C_SEND_RESTART,       // I2C_SEND_RESTART
    ECC_I2C_do_I2C_SEND_STOP,          // I2C_SEND_STOP
    ECC_I2C_do_I2C_RX_DO_ACK,          // I2C_RX_DO_ACK
    ECC_I2C_do_I2C_TX_DO_ACK,          // I2C_TX_DO_ACK
    ECC_I2C_do_I2C_DO_NACK_STOP,       // I2C_RX_DO_NACK_STOP
    ECC_I2C_do_I2C_DO_NACK_RESTART,    // I2C_RX_DO_NACK_RESTART
    ECC_I2C_do_I2C_RESET,              // I2C_RESET
    ECC_I2C_do_I2C_DO_ADDRESS_NACK,    // I2C_ADDRESS_NACK
    ECC_I2C_do_I2C_BUS_COLLISION,      // I2C_BUS_COLLISION
    ECC_I2C_do_I2C_BUS_ERROR           // I2C_BUS_ERROR
};

void ECC_I2C_master_isr(void)
{
	TWI0.MSTATUS |= (TWI_RIF_bm | TWI_WIF_bm);

	// NOTE: We are ignoring the Write Collision flag.

	// Address phase received NACK from slave, override next state
	if (ECC_I2C_status.addressNACKCheck && (TWI0.MSTATUS & TWI_RXACK_bm)) {
		ECC_I2C_status.state = I2C_ADDRESS_NACK; // State Override
	}

	// Bus arbitration lost to another master, override next state
	if (TWI0.MSTATUS & TWI_ARBLOST_bm) {
		ECC_I2C_status.state = I2C_BUS_COLLISION; // State Override
	}

	// Bus error, override next state
	if (TWI0.MSTATUS & TWI_BUSERR_bm) {
		ECC_I2C_status.state = I2C_BUS_ERROR; // State Override
	}

	ECC_I2C_status.state = ECC_I2C_fsmStateTable[ECC_I2C_status.state]();
}

/************************************************************************/
/* Helper Functions                                                     */
/************************************************************************/
static i2c_operations_t ECC_I2C_return_stop(void *p)
{
	return i2c_stop;
}

static i2c_operations_t ECC_I2C_return_reset(void *p)
{
	return i2c_reset_link;
}

static void ECC_I2C_set_callback(i2c_callback_index idx, i2c_callback cb, void *p)
{
	if (cb) {
		ECC_I2C_status.callbackTable[idx]   = cb;
		ECC_I2C_status.callbackPayload[idx] = p;
	} else {
		ECC_I2C_status.callbackTable[idx]   = ECC_I2C_return_stop;
		ECC_I2C_status.callbackPayload[idx] = NULL;
	}
}
