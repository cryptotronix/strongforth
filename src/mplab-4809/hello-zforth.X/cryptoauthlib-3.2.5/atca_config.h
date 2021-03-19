/* Auto-generated config file atca_config.h */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

#define ATCA_NO_PRAGMA_PACK

/* Included HALS */
//#define ATCA_HAL_KIT_HID
//#define ATCA_HAL_KIT_CDC
#define ATCA_HAL_I2C
//#define ATCA_HAL_SPI
//#define ATCA_HAL_KIT_BRIDGE
//#define ATCA_HAL_CUSTOM

/* Included device support */
//#define ATCA_ATSHA204A_SUPPORT
//#define ATCA_ATSHA206A_SUPPORT
//#define ATCA_ATECC108A_SUPPORT
//#define ATCA_ATECC508A_SUPPORT
#define ATCA_ATECC608_SUPPORT
//#define ATCA_TA100_SUPPORT

/** Device Override - Library Assumes ATECC608B support in checks */
#define ATCA_ATECC608A_SUPPORT

#ifdef ATCA_TA100_SUPPORT
#define ATCA_TA100_AES_AUTH_SUPPORT
#endif

/** Define if cryptoauthlib is to use the maximum execution time method */
//#define ATCA_NO_POLL


/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

/***************** Diagnostic & Test Configuration Section *****************/

/** Enable debug messages */
//#define ATCA_PRINTF

/** Enable to build in test hooks */
//#define ATCA_TESTS_ENABLED

/******************** Features Configuration Section ***********************/

/** Define certificate templates to be supported. */
//#define ATCA_TNGTLS_SUPPORT
//#define ATCA_TNGLORA_SUPPORT
//#define ATCA_TFLEX_SUPPORT
//#define ATCA_TNG_LEGACY_SUPPORT

/** Define Software Crypto Library to Use - if none are defined use the
    cryptoauthlib version where applicable */
//#define ATCA_MBEDTLS
//#define ATCA_OPENSSL
//#define ATCA_WOLFSSL

/** Additional Runtime Configuration */
//#define ATCA_LIBRARY_CONF  "@ATCA_LIBRARY_CONF@"

/** Define to build atcab_ functions rather that defining them as macros */
//#define ATCA_USE_ATCAB_FUNCTIONS

/******************** Platform Configuration Section ***********************/

/** Define if the library is not to use malloc/free */
#define ATCA_NO_HEAP

/** Define platform malloc/free */
//#define ATCA_PLATFORM_MALLOC    @ATCA_PLATFORM_MALLOC@
//#define ATCA_PLATFORM_FREE      @ATCA_PLATFORM_FREE@

#define atca_delay_ms   hal_delay_ms
#define atca_delay_us   hal_delay_us

#endif // ATCA_CONFIG_H
