
Strongforth
===========


Strongforth is the scripting backend that powers the Strongheld protocol system. Combining the portability and customization of the FORTH language family with the Microchip Cryptoauthlib library, it provides Strongheld the flexibility which makes it uniquely suited for embedded security solutions.

## Strong

Strongheld (from which Strongforth gets its name) is set of protocols built upon transport-layer agonistic services. Strongheld is more like a framework or even a philosophy, it contains various components and implementations. The core requirements is that a Microchip ATECC608 device exists in your deployment somewhere, one endpoint can use this ATECC608, and you have at least one other component with a means to communication. For example, you could have:

* A combo BLE+MCU SoC with an ATECC608 over I2C with Strongheld, communicating over BLE to a mobile that implements Strongheld.
* The same BLE SoC that communicates through the mobile to a backend server that runs Strongheld.

* An 8-bit AVR with a sub GHz transceiver with an ATECC608 running Strongheld, sending messages to a Linux gateway that also has an ATECC608 running Strongheld.

* A USB only peripheral with an ATECC608 running Strongheld and a server.

Whether wired or wireless, fast or slow, Strongheld is really for any two peers from AVRs and up to authentication and communicate relatively small messages.

## Forth

FORTH, which Strongforth utilizes for its core functionality, is a mature langauge that can be implimented with a very small footprint and flexible applications. There are many different flavors of FORTH that have been written for many diffrent languages, but we chose [zForth](https://github.com/zevv/zForth) due to the minimal memory usage and C codebase. Strongforth has a few major differences from the zForth core, such as:

* An API which allows for the interpreter to be run within a larger application, instead of a terminal-based REPL.

* An optional whitelist that will prevent the use of any undesired words, providing a level of sandboxing security.

* An optional static/constant dictionary, which prevents any unwanted manipulation of the language definition.

* The ability to store and work with large cryptographic values.

Knowledge of FORTH is not necessary to use Strongforth, as much of the langauge has been abstracted away when using the pre-made flow patterns.


## Deployment Targets

* An embedded device with an ATECC608. Typically this device does not have an IP stack but has some transport of delivery messages to device that does, e.g. Bluetooth. This device will run strongforth as a C library.
* A mobile device. In this case, Bluetooth is most likely the medium with the device. There are several options for using Strongheld here. If using a native app, one can add a very small binding around Strongforth. Alternatively, we provide an emscripten javascript target for use in browser environments. In this case, the mobile could even use Web-BLE with Chrome.
* A cloud environment. Here, Strongforth runs in a docker container with a simple REST api.

## Use Cases

Below are listed some usecases we have identified and added support for. The modular nature of Strongforth allows for more, however these are the main flows that we intend to support for now.

### Authenticated Commands

An external component, like a mobile or a cloud, wants to send an authenticated command to an specific device.

#### When to use

You need mutual authentication of a one-time command. For example, initial device provisioning of a BLE/WiFi enabled device. In this situation, the device must be onboarded to the user's account on the cloud. Therefore, this cloud must also ensure the device is authenticated before onboarding. Similarly, the device needs to verify the authorized cloud before allowing the onboarding operation.


Besides a provisioning use case, another use case is higher security commands like "unlock" or "arm."



```
more details to come.
```

### Accessory Authentication

A device, such as a mobile or gateway, wants to prove that another device containing an ATECC608 is authentic.

#### When to use

One-auth, lightweight authentication of the target devices.



```
more details to come.
```

### Session Encryption

Two components, one with an ATECC608 used to mutually authenticate, participate in a key exchange and subsequently enter an encrypted session.

#### When to Use
A device needs to send and receive encrypted messages that are end-to-end protected. Additionally the following constraints are placed on this protocol:

* A trusted public key is authorized in slot 14 which matches one-end of the communicating parties.
* The server implementation is using the provided docker container, in which no state is maintained. Therefore the calling application has a mechanism to store state and provide it to the container.
* The encrypted messages are 1 to 28 bytes long.
* The two parties can maintain an incrementing message counter.



```
more details to come.
```

