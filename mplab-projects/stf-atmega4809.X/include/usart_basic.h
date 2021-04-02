/**
 * \file
 *
 * \brief USART basic driver.
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

#ifndef USART_BASIC_H_INCLUDED
#define USART_BASIC_H_INCLUDED

#include <atmel_start.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Normal Mode, Baud register value */
#define USART0_BAUD_RATE(BAUD_RATE) ((float)(20000000 * 64 / (16 * (float)BAUD_RATE)) + 0.5)

int8_t DBG_UART_init();

void DBG_UART_enable();

void DBG_UART_enable_rx();

void DBG_UART_enable_tx();

void DBG_UART_disable();

uint8_t DBG_UART_get_data();

bool DBG_UART_is_tx_ready();

bool DBG_UART_is_rx_ready();

bool DBG_UART_is_tx_busy();

uint8_t DBG_UART_read(void);

void DBG_UART_write(const uint8_t data);

/* Normal Mode, Baud register value */
#define USART1_BAUD_RATE(BAUD_RATE) ((float)(20000000 * 64 / (16 * (float)BAUD_RATE)) + 0.5)

int8_t BLE_UART_init();

void BLE_UART_enable();

void BLE_UART_enable_rx();

void BLE_UART_enable_tx();

void BLE_UART_disable();

uint8_t BLE_UART_get_data();

bool BLE_UART_is_tx_ready();

bool BLE_UART_is_rx_ready();

bool BLE_UART_is_tx_busy();

uint8_t BLE_UART_read(void);

void BLE_UART_write(const uint8_t data);

#ifdef __cplusplus
}
#endif

#endif /* USART_BASIC_H_INCLUDED */
