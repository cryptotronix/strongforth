const TRANSPARENT_UART_SERVICE = '49535343-fe7d-4ae5-8fa9-9fafd205e455';
const TRANSPARENT_UART_TX_CHAR = '49535343-8841-43f4-a8d4-ecbe34729bb3';
const TRANSPARENT_UART_RX_CHAR = '49535343-1e4d-4bd9-ba61-23c647249616';

const CMD_GET_DEVICE_PUBKEY	= 0xA1;
const CMD_STORE_SERVER_PUBKEY =	0xA2;
const CMD_GET_COUNTER_MSG =	0xA3;
const CMD_VERIFY_AUTH_MSG = 0xA4;
const CMD_OK = 0xAA;
const CMD_BAD = 0xBD;

const WAIT_TIME = 100;
const MAX_WAIT = 10000;

var bleDevice = null;
var readChar = null;
var writeChar = null;

var rxLen = 0;
var rxBuf = new Uint8Array(512);

function log() {
    var line = Array.prototype.slice.call(arguments).map(function(argument) {
        return typeof argument === 'string' ? argument : JSON.stringify(argument);
    }).join(' ');

    console.log(line);
    var logRow = document.querySelector('#logRow');
    var preLog = document.querySelector('#log');
    preLog.textContent += '> ' + line + '\n';
    logRow.scrollTop = logRow.scrollHeight;
}

function waitForRx() {
    return new Promise((resolve, reject) => {
        let waitCount = 0;
        function checkLen() {
            waitCount += WAIT_TIME;
            if (rxLen > 0) {
                return resolve();
            }
            if (waitCount > MAX_WAIT) {
                return reject(new Error("Timed out waiting for Rx"));
            }
            setTimeout(checkLen, WAIT_TIME);
        }
        checkLen();
    });
}

// function getSupportedProperties(characteristic) {
//     let supportedProperties = [];
//     for (const p in characteristic.properties) {
//         if (characteristic.properties[p] === true) {
//             supportedProperties.push(p.toUpperCase());
//         }
//     }
//     return '[' + supportedProperties.join(', ') + ']';
// }

function handleRxCharChanged(event) {
    let value = event.target.value;
    let a = [];
    rxLen = value.byteLength;

    for (let i = 0; i < rxLen; i++) {
        a.push('0x' + ('00' + value.getUint8(i).toString(16)).slice(-2));
        rxBuf[i] = value.getUint8(i);
    }
    let resBuf = rxBuf.slice(0, rxLen);
    let respStr = new TextDecoder().decode(resBuf);
    log(respStr);
}

function connected() {
    $('#sendBtn').removeAttr('disabled');
    $('#disconnectBtn').removeAttr('disabled');
    $('#connectBtn').attr('disabled', true);
}

function disconnected() {
    $('#sendBtn').attr('disabled', true);
    $('#disconnectBtn').attr('disabled', true);
    $('#connectBtn').removeAttr('disabled');
}

async function connectDevice() {
    if (bleDevice.gatt.connected && readChar && writeChar) {
        connected();
        return;
    }

    log('Connecting to GATT Server...');

    bleDevice.addEventListener('gattserverdisconnected', onDisconnected);
    const server = await bleDevice.gatt.connect();

    log('OK!');
    log('Getting Transparent UART Service...');

    const service = await server.getPrimaryService(TRANSPARENT_UART_SERVICE);

    log('OK!');
    log('Getting Tx Characteristic...');

    writeChar = await service.getCharacteristic(TRANSPARENT_UART_TX_CHAR);

    log('OK!');
    log('Getting Rx Characteristic...');

    readChar = await service.getCharacteristic(TRANSPARENT_UART_RX_CHAR);

    log('OK!');
    log('Starting Rx Notifications...');

    readChar.addEventListener('characteristicvaluechanged', handleRxCharChanged);
    readChar.startNotifications();

    log('OK!');

    connected();
}

async function onDisconnected() {
    log('Disconnected, trying to reconnect...');
    try {
        disconnected();
        await connectDevice();
    } catch (error) {
        log('Error! ' + error);
    }
}

async function getDevice() {
    let options = {
        filters: [
            {namePrefix: 'RN4870'},
        ],
        optionalServices: [
            TRANSPARENT_UART_SERVICE,
        ],
    };

    log('Requesting RN4870 Device...');

    bleDevice = await navigator.bluetooth.requestDevice(options);
}

async function onConnectBtnClick() {
    try {
        if (!bleDevice) {
            await getDevice();
        }
        await connectDevice();

    } catch(error) {
        log('Connect Error! ' + error);
    }
}

async function onDisconnectBtnClick() {
    try {
        if (!bleDevice) {
            return;
        } else if (!bleDevice.gatt.connected) {
            return;
        }

        log('Disconnecting...');
        bleDevice.removeEventListener('gattserverdisconnected', onDisconnected);
        bleDevice.gatt.disconnect();

        disconnected();

        log('OK!');
    } catch(error) {
        log('Disconnect Error! ' + error);
    }
}

async function onLoopbackBtnClick() {
    log('Loopback test...');
    try {
        const u8arr = new TextEncoder().encode('1 1 + 1 sys\n');
        await writeChar.writeValue(u8arr);
    } catch(error) {
        log('Loopback Error! ' + error);
    }
}

async function onSendBtnClick() {
    if (!$('#stfText').val()) {
        $('#stfText').addClass('is-invalid');
    } else {
        $('#stfText').removeClass('is-invalid');
        let stfText = $('#stfText').val();

        rxLen = 0;

        try {
            log('Sending: ' + stfText);
            const u8arr = new TextEncoder().encode(stfText + '\n');
            await writeChar.writeValue(u8arr);           
        } catch(error) {
            log('Error! ' + error);
        }
    }
}

function isWebBluetoothEnabled() {
    if (navigator.bluetooth) {
        return true;
    } else {
        return false;
    }
}

function showNoBTAlert() {
    $('#noBTAlert').removeClass('d-none');
}

function showMainForm() {
    $('#mainForm').removeClass('d-none');
}

document.querySelector('#connectBtn').addEventListener('click', onConnectBtnClick);
document.querySelector('#disconnectBtn').addEventListener('click', onDisconnectBtnClick);
document.querySelector('#sendBtn').addEventListener('click', onSendBtnClick);

document.addEventListener('DOMContentLoaded', async function() {

    log('Checking for Web BLE API support...');

    try {
        if (!isWebBluetoothEnabled()) {
            log('no navigator.bluetooth detected!');
            // its not even enabled so just show the alert
            showNoBTAlert();
        } else {
            // if navigator.bluetooth exists we still need to check
            // because it may blocked
            const resp = await navigator.bluetooth.getAvailability();

            if (!resp) {
                log('navigator.bluetooth.getAvailability returned false!');
                showNoBTAlert();
            } else {
                log('OK!');
                showMainForm();
            }
        }
    } catch (err) {
        log('error: ' + err);
    }
});
