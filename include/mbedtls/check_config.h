/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_CHECK_CONFIG_H
#define MBEDTLS_CHECK_CONFIG_H

/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "mbed TLS requires a platform with 8-bit chars"
#endif

#if defined(_WIN32)
#if !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_C is required on Windows"
#endif

/* Fix the config here. Not convenient to put an #ifdef _WIN32 in mbedtls_config.h as
 * it would confuse config.py. */
#if !defined(MBEDTLS_PLATFORM_SNPRINTF_ALT) && \
    !defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO)
#define MBEDTLS_PLATFORM_SNPRINTF_ALT
#endif

#if !defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT) && \
    !defined(MBEDTLS_PLATFORM_VSNPRINTF_MACRO)
#define MBEDTLS_PLATFORM_VSNPRINTF_ALT
#endif
#endif /* _WIN32 */

#if defined(TARGET_LIKE_MBED) && defined(MBEDTLS_NET_C)
#error "The NET module is not available for mbed OS - please use the network functions provided by Mbed OS"
#endif

#if defined(MBEDTLS_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "MBEDTLS_DEPRECATED_WARNING only works with GCC and Clang"
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_HAVE_TIME)
#error "MBEDTLS_HAVE_TIME_DATE without MBEDTLS_HAVE_TIME does not make sense"
#endif

#if defined(MBEDTLS_AESNI_C) && !defined(MBEDTLS_HAVE_ASM)
#error "MBEDTLS_AESNI_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_CTR_DRBG_C) && !defined(MBEDTLS_AES_C)
#error "MBEDTLS_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_DHM_C) && !defined(MBEDTLS_BIGNUM_C)
#error "MBEDTLS_DHM_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_CMAC_C) && \
    !defined(MBEDTLS_AES_C) && !defined(MBEDTLS_DES_C)
#error "MBEDTLS_CMAC_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_NIST_KW_C) && \
    ( !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_CIPHER_C) )
#error "MBEDTLS_NIST_KW_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECDH_C) && !defined(MBEDTLS_ECP_C)
#error "MBEDTLS_ECDH_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECDSA_C) &&            \
    ( !defined(MBEDTLS_ECP_C) ||           \
      !( defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_BP256R1_ENABLED) ||   \
         defined(MBEDTLS_ECP_DP_BP384R1_ENABLED) ||   \
         defined(MBEDTLS_ECP_DP_BP512R1_ENABLED) ) || \
      !defined(MBEDTLS_ASN1_PARSE_C) ||    \
      !defined(MBEDTLS_ASN1_WRITE_C) )
#error "MBEDTLS_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECJPAKE_C) &&           \
    ( !defined(MBEDTLS_ECP_C) || !defined(MBEDTLS_MD_C) )
#error "MBEDTLS_ECJPAKE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)           && \
    ( defined(MBEDTLS_USE_PSA_CRYPTO)          || \
      defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT) || \
      defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)     || \
      defined(MBEDTLS_ECDSA_SIGN_ALT)          || \
      defined(MBEDTLS_ECDSA_VERIFY_ALT)        || \
      defined(MBEDTLS_ECDSA_GENKEY_ALT)        || \
      defined(MBEDTLS_ECP_INTERNAL_ALT)        || \
      defined(MBEDTLS_ECP_ALT) )
#error "MBEDTLS_ECP_RESTARTABLE defined, but it cannot coexist with an alternative or PSA-based ECP implementation"
#endif

#if defined(MBEDTLS_ECDSA_DETERMINISTIC) && !defined(MBEDTLS_HMAC_DRBG_C)
#error "MBEDTLS_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_C) && ( !defined(MBEDTLS_BIGNUM_C) || (    \
    !defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) &&                 \
    !defined(MBEDTLS_ECP_DP_CURVE448_ENABLED) ) )
#error "MBEDTLS_ECP_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_PARSE_C) && !defined(MBEDTLS_ASN1_PARSE_C)
#error "MBEDTLS_PK_PARSE_C defined, but not all prerequesites"
#endif

#if defined(MBEDTLS_ENTROPY_C) && (!defined(MBEDTLS_SHA512_C) &&      \
                                    !defined(MBEDTLS_SHA256_C))
#error "MBEDTLS_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_SHA512_C) &&         \
    defined(MBEDTLS_CTR_DRBG_ENTROPY_LEN) && (MBEDTLS_CTR_DRBG_ENTROPY_LEN > 64)
#error "MBEDTLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(MBEDTLS_ENTROPY_C) &&                                            \
    ( !defined(MBEDTLS_SHA512_C) || defined(MBEDTLS_ENTROPY_FORCE_SHA256) ) \
    && defined(MBEDTLS_CTR_DRBG_ENTROPY_LEN) && (MBEDTLS_CTR_DRBG_ENTROPY_LEN > 32)
#error "MBEDTLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_ENTROPY_FORCE_SHA256) && !defined(MBEDTLS_SHA256_C)
#error "MBEDTLS_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define MBEDTLS_HAS_MEMSAN
#endif
#endif
#if defined(MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN) &&  !defined(MBEDTLS_HAS_MEMSAN)
#error "MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN requires building with MemorySanitizer"
#endif
#undef MBEDTLS_HAS_MEMSAN

#if defined(MBEDTLS_GCM_C) && (                                        \
        !defined(MBEDTLS_AES_C) && !defined(MBEDTLS_CAMELLIA_C) && !defined(MBEDTLS_ARIA_C) )
#error "MBEDTLS_GCM_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_RANDOMIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_ADD_MIXED_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_ADD_MIXED_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_DOUBLE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_NORMALIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_RANDOMIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_NORMALIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && !defined(MBEDTLS_ECP_INTERNAL_ALT)
#error "MBEDTLS_ECP_NO_FALLBACK defined, but no alternative implementation enabled"
#endif

#if defined(MBEDTLS_HKDF_C) && !defined(MBEDTLS_MD_C)
#error "MBEDTLS_HKDF_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_HMAC_DRBG_C) && !defined(MBEDTLS_MD_C)
#error "MBEDTLS_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(MBEDTLS_ECDH_C) || !defined(MBEDTLS_ECDSA_C) ||          \
      !defined(MBEDTLS_X509_CRT_PARSE_C) )
#error "MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(MBEDTLS_ECDH_C) || !defined(MBEDTLS_RSA_C) ||          \
      !defined(MBEDTLS_X509_CRT_PARSE_C) )
#error "MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(MBEDTLS_DHM_C)
#error "MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(MBEDTLS_ECDH_C)
#error "MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(MBEDTLS_DHM_C) || !defined(MBEDTLS_RSA_C) ||           \
      !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_PKCS1_V15) )
#error "MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(MBEDTLS_ECDH_C) || !defined(MBEDTLS_RSA_C) ||          \
      !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_PKCS1_V15) )
#error "MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(MBEDTLS_ECDH_C) || !defined(MBEDTLS_ECDSA_C) ||          \
      !defined(MBEDTLS_X509_CRT_PARSE_C) )
#error "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) || \
      !defined(MBEDTLS_PKCS1_V15) )
#error "MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) || \
      !defined(MBEDTLS_PKCS1_V15) )
#error "MBEDTLS_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) &&                    \
    ( !defined(MBEDTLS_ECJPAKE_C) || !defined(MBEDTLS_SHA256_C) ||      \
      !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) )
#error "MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) &&        \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE) &&              \
    ( !defined(MBEDTLS_SHA256_C) &&                             \
      !defined(MBEDTLS_SHA512_C) &&                             \
      !defined(MBEDTLS_SHA1_C) )
#error "!MBEDTLS_SSL_KEEP_PEER_CERTIFICATE requires MBEDTLS_SHA512_C, MBEDTLS_SHA256_C or MBEDTLS_SHA1_C"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_PLATFORM_MEMORY) )
#error "MBEDTLS_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_MEMORY_BACKTRACE) && !defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#error "MBEDTLS_MEMORY_BACKTRACE defined, but not all prerequesites"
#endif

#if defined(MBEDTLS_MEMORY_DEBUG) && !defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#error "MBEDTLS_MEMORY_DEBUG defined, but not all prerequesites"
#endif

#if defined(MBEDTLS_PADLOCK_C) && !defined(MBEDTLS_HAVE_ASM)
#error "MBEDTLS_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PEM_PARSE_C) && !defined(MBEDTLS_BASE64_C)
#error "MBEDTLS_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PEM_WRITE_C) && !defined(MBEDTLS_BASE64_C)
#error "MBEDTLS_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_C) && \
    ( !defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_ECP_C) )
#error "MBEDTLS_PK_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_PARSE_C) && !defined(MBEDTLS_PK_C)
#error "MBEDTLS_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_WRITE_C) && !defined(MBEDTLS_PK_C)
#error "MBEDTLS_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_EXIT) ||\
        defined(MBEDTLS_PLATFORM_EXIT_ALT) )
#error "MBEDTLS_PLATFORM_EXIT_MACRO and MBEDTLS_PLATFORM_STD_EXIT/MBEDTLS_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_ALT) &&\
    ( !defined(MBEDTLS_PLATFORM_C) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_TIME_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_TIME) ||\
        defined(MBEDTLS_PLATFORM_TIME_ALT) )
#error "MBEDTLS_PLATFORM_TIME_MACRO and MBEDTLS_PLATFORM_STD_TIME/MBEDTLS_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_TIME) ||\
        defined(MBEDTLS_PLATFORM_TIME_ALT) )
#error "MBEDTLS_PLATFORM_TIME_TYPE_MACRO and MBEDTLS_PLATFORM_STD_TIME/MBEDTLS_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_FPRINTF) ||\
        defined(MBEDTLS_PLATFORM_FPRINTF_ALT) )
#error "MBEDTLS_PLATFORM_FPRINTF_MACRO and MBEDTLS_PLATFORM_STD_FPRINTF/MBEDTLS_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_FREE_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_PLATFORM_MEMORY) )
#error "MBEDTLS_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_FREE_MACRO) &&\
    defined(MBEDTLS_PLATFORM_STD_FREE)
#error "MBEDTLS_PLATFORM_FREE_MACRO and MBEDTLS_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_FREE_MACRO) && !defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
#error "MBEDTLS_PLATFORM_CALLOC_MACRO must be defined if MBEDTLS_PLATFORM_FREE_MACRO is"
#endif

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_PLATFORM_MEMORY) )
#error "MBEDTLS_PLATFORM_CALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&\
    defined(MBEDTLS_PLATFORM_STD_CALLOC)
#error "MBEDTLS_PLATFORM_CALLOC_MACRO and MBEDTLS_PLATFORM_STD_CALLOC cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO) && !defined(MBEDTLS_PLATFORM_FREE_MACRO)
#error "MBEDTLS_PLATFORM_FREE_MACRO must be defined if MBEDTLS_PLATFORM_CALLOC_MACRO is"
#endif

#if defined(MBEDTLS_PLATFORM_MEMORY) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_PRINTF) ||\
        defined(MBEDTLS_PLATFORM_PRINTF_ALT) )
#error "MBEDTLS_PLATFORM_PRINTF_MACRO and MBEDTLS_PLATFORM_STD_PRINTF/MBEDTLS_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_SNPRINTF) ||\
        defined(MBEDTLS_PLATFORM_SNPRINTF_ALT) )
#error "MBEDTLS_PLATFORM_SNPRINTF_MACRO and MBEDTLS_PLATFORM_STD_SNPRINTF/MBEDTLS_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_STD_MEM_HDR) &&\
    !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
#error "MBEDTLS_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_CALLOC) && !defined(MBEDTLS_PLATFORM_MEMORY)
#error "MBEDTLS_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_FREE) && !defined(MBEDTLS_PLATFORM_MEMORY)
#error "MBEDTLS_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_EXIT) &&\
    !defined(MBEDTLS_PLATFORM_EXIT_ALT)
#error "MBEDTLS_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_TIME) &&\
    ( !defined(MBEDTLS_PLATFORM_TIME_ALT) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_STD_TIME defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_FPRINTF) &&\
    !defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
#error "MBEDTLS_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_PRINTF) &&\
    !defined(MBEDTLS_PLATFORM_PRINTF_ALT)
#error "MBEDTLS_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_SNPRINTF) &&\
    !defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
#error "MBEDTLS_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_ENTROPY_C) )
#error "MBEDTLS_ENTROPY_NV_SEED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT) &&\
    !defined(MBEDTLS_ENTROPY_NV_SEED)
#error "MBEDTLS_PLATFORM_NV_SEED_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ) &&\
    !defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
#error "MBEDTLS_PLATFORM_STD_NV_SEED_READ defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE) &&\
    !defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
#error "MBEDTLS_PLATFORM_STD_NV_SEED_WRITE defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_READ_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ) ||\
      defined(MBEDTLS_PLATFORM_NV_SEED_ALT) )
#error "MBEDTLS_PLATFORM_NV_SEED_READ_MACRO and MBEDTLS_PLATFORM_STD_NV_SEED_READ cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE) ||\
      defined(MBEDTLS_PLATFORM_NV_SEED_ALT) )
#error "MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO and MBEDTLS_PLATFORM_STD_NV_SEED_WRITE cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C) &&                                    \
    !( ( ( defined(MBEDTLS_CTR_DRBG_C) || defined(MBEDTLS_HMAC_DRBG_C) ) && \
         defined(MBEDTLS_ENTROPY_C) ) ||                                \
       defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) )
#error "MBEDTLS_PSA_CRYPTO_C defined, but not all prerequisites (missing RNG)"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SPM) && !defined(MBEDTLS_PSA_CRYPTO_C)
#error "MBEDTLS_PSA_CRYPTO_SPM defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C) &&    \
    ! ( defined(MBEDTLS_PSA_CRYPTO_C) && \
        defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) )
#error "MBEDTLS_PSA_CRYPTO_SE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) &&            \
    ! defined(MBEDTLS_PSA_CRYPTO_C)
#error "MBEDTLS_PSA_CRYPTO_STORAGE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY) &&      \
    !( defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) && \
       defined(MBEDTLS_ENTROPY_NV_SEED) )
#error "MBEDTLS_PSA_INJECT_ENTROPY defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY) &&              \
    !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
#error "MBEDTLS_PSA_INJECT_ENTROPY is not compatible with actual entropy sources"
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY) &&              \
    defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
#error "MBEDTLS_PSA_INJECT_ENTROPY is not compatible with MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG"
#endif

#if defined(MBEDTLS_PSA_ITS_FILE_C) && \
    !defined(MBEDTLS_FS_IO)
#error "MBEDTLS_PSA_ITS_FILE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER) && \
    defined(MBEDTLS_USE_PSA_CRYPTO)
#error "MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined, but it cannot coexist with MBEDTLS_USE_PSA_CRYPTO."
#endif

#if defined(MBEDTLS_RSA_C) && ( !defined(MBEDTLS_BIGNUM_C) ||         \
    !defined(MBEDTLS_OID_C) )
#error "MBEDTLS_RSA_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_RSA_C) && ( !defined(MBEDTLS_PKCS1_V21) &&         \
    !defined(MBEDTLS_PKCS1_V15) )
#error "MBEDTLS_RSA_C defined, but none of the PKCS1 versions enabled"
#endif

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_PKCS1_V21) )
#error "MBEDTLS_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SHA384_C) && !defined(MBEDTLS_SHA512_C)
#error "MBEDTLS_SHA384_C defined without MBEDTLS_SHA512_C"
#endif

#if defined(MBEDTLS_SHA224_C) && !defined(MBEDTLS_SHA256_C)
#error "MBEDTLS_SHA224_C defined without MBEDTLS_SHA256_C"
#endif

#if defined(MBEDTLS_SHA256_C) && !defined(MBEDTLS_SHA224_C)
#error "MBEDTLS_SHA256_C defined without MBEDTLS_SHA224_C"
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && ( !defined(MBEDTLS_SHA1_C) &&     \
    !defined(MBEDTLS_SHA256_C) && !defined(MBEDTLS_SHA512_C) )
#error "MBEDTLS_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && ( !defined(MBEDTLS_HKDF_C) && \
    !defined(MBEDTLS_SHA256_C) && !defined(MBEDTLS_SHA512_C) )
#error "MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) &&                                    \
    !(defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) ||                          \
      defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) ||                      \
      defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) ||                    \
      defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) ||                  \
      defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) ||                     \
      defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) ||                   \
      defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) ||                          \
      defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) ||                      \
      defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) ||                      \
      defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) ||                    \
      defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) )
#error "One or more versions of the TLS protocol are enabled " \
        "but no key exchange methods defined with MBEDTLS_KEY_EXCHANGE_xxxx"
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)     && \
    !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#error "MBEDTLS_SSL_PROTO_DTLS defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_CLI_C) && !defined(MBEDTLS_SSL_TLS_C)
#error "MBEDTLS_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_TLS_C) && ( !defined(MBEDTLS_CIPHER_C) ||     \
    !defined(MBEDTLS_MD_C) )
#error "MBEDTLS_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_SRV_C) && !defined(MBEDTLS_SSL_TLS_C)
#error "MBEDTLS_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_TLS_C) && !defined(MBEDTLS_SSL_PROTO_TLS1_2) && !defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#error "MBEDTLS_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && !defined(MBEDTLS_SSL_PROTO_DTLS)
#error "MBEDTLS_SSL_DTLS_HELLO_VERIFY  defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && !defined(MBEDTLS_SSL_SRV_C)
#error "MBEDTLS_SSL_DTLS_HELLO_VERIFY  defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && \
    !defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
#error "MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE  defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY) &&                              \
    ( !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) )
#error "MBEDTLS_SSL_DTLS_ANTI_REPLAY  defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID) &&                              \
    ( !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) )
#error "MBEDTLS_SSL_DTLS_CONNECTION_ID  defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)            &&                 \
    defined(MBEDTLS_SSL_CID_IN_LEN_MAX) &&                 \
    MBEDTLS_SSL_CID_IN_LEN_MAX > 255
#error "MBEDTLS_SSL_CID_IN_LEN_MAX too large (max 255)"
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)            &&                  \
    defined(MBEDTLS_SSL_CID_OUT_LEN_MAX) &&                 \
    MBEDTLS_SSL_CID_OUT_LEN_MAX > 255
#error "MBEDTLS_SSL_CID_OUT_LEN_MAX too large (max 255)"
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC) &&   \
    !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#error "MBEDTLS_SSL_ENCRYPT_THEN_MAC defined, but not all prerequsites"
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET) && \
    !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#error "MBEDTLS_SSL_EXTENDED_MASTER_SECRET defined, but not all prerequsites"
#endif

#if defined(MBEDTLS_SSL_TICKET_C) && !defined(MBEDTLS_CIPHER_C)
#error "MBEDTLS_SSL_TICKET_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && \
        !defined(MBEDTLS_X509_CRT_PARSE_C)
#error "MBEDTLS_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_THREADING_PTHREAD)
#if !defined(MBEDTLS_THREADING_C) || defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define MBEDTLS_THREADING_IMPL
#endif

#if defined(MBEDTLS_THREADING_ALT)
#if !defined(MBEDTLS_THREADING_C) || defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_ALT defined, but not all prerequisites"
#endif
#define MBEDTLS_THREADING_IMPL
#endif

#if defined(MBEDTLS_THREADING_C) && !defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_C defined, single threading implementation required"
#endif
#undef MBEDTLS_THREADING_IMPL

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_PSA_CRYPTO_C)
#error "MBEDTLS_USE_PSA_CRYPTO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_VERSION_FEATURES) && !defined(MBEDTLS_VERSION_C)
#error "MBEDTLS_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_USE_C) && ( !defined(MBEDTLS_BIGNUM_C) ||  \
    !defined(MBEDTLS_OID_C) || !defined(MBEDTLS_ASN1_PARSE_C) ||      \
    !defined(MBEDTLS_PK_PARSE_C) )
#error "MBEDTLS_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_CREATE_C) && ( !defined(MBEDTLS_BIGNUM_C) ||  \
    !defined(MBEDTLS_OID_C) || !defined(MBEDTLS_ASN1_WRITE_C) ||       \
    !defined(MBEDTLS_PK_WRITE_C) )
#error "MBEDTLS_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && ( !defined(MBEDTLS_X509_USE_C) )
#error "MBEDTLS_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_CRL_PARSE_C) && ( !defined(MBEDTLS_X509_USE_C) )
#error "MBEDTLS_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C) && ( !defined(MBEDTLS_X509_USE_C) )
#error "MBEDTLS_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_CRT_WRITE_C) && ( !defined(MBEDTLS_X509_CREATE_C) )
#error "MBEDTLS_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_X509_CSR_WRITE_C) && ( !defined(MBEDTLS_X509_CREATE_C) )
#error "MBEDTLS_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_HAVE_INT32) && defined(MBEDTLS_HAVE_INT64)
#error "MBEDTLS_HAVE_INT32 and MBEDTLS_HAVE_INT64 cannot be defined simultaneously"
#endif /* MBEDTLS_HAVE_INT32 && MBEDTLS_HAVE_INT64 */

#if ( defined(MBEDTLS_HAVE_INT32) || defined(MBEDTLS_HAVE_INT64) ) && \
    defined(MBEDTLS_HAVE_ASM)
#error "MBEDTLS_HAVE_INT32/MBEDTLS_HAVE_INT64 and MBEDTLS_HAVE_ASM cannot be defined simultaneously"
#endif /* (MBEDTLS_HAVE_INT32 || MBEDTLS_HAVE_INT64) && MBEDTLS_HAVE_ASM */

#if defined(MBEDTLS_SSL_DTLS_SRTP) && ( !defined(MBEDTLS_SSL_PROTO_DTLS) )
#error "MBEDTLS_SSL_DTLS_SRTP defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && ( !defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) )
#error "MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) &&           \
    defined(MBEDTLS_ZERO_RTT)         &&                        \
    ( !defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) ||             \
      !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) )
#error "ZeroRTT requires MBEDTLS_ZERO_RTT and MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED to be defined."
#endif

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE) && \
    !defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#error "MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE defined, but not all prerequesites."
#endif

/*
 * The following extensions are no longer applicable to TLS 1.3,
 * although TLS 1.3 clients MAY send them if they are willing to negotiate
 * them with prior versions of TLS.TLS 1.3 servers MUST ignore these extensions
 * if they are negotiating TLS 1.3:
 *
 *  - srp[RFC5054]
 *  - encrypt_then_mac[RFC7366]
 *  - extended_master_secret[RFC7627]
 *  - SessionTicket[RFC5077], and
 *  - renegotiation_info[RFC5746].
 */

 /* Encrypt-then-Mac extension is not applicable to TLS 1.3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#error "Encrypt-then-Mac extension is not applicable to TLS 1.3"
#endif

/* Key derivation works differently in TLS 1.3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
#error "Extended master secret extension is not applicable to TLS 1.3"
#endif

 /* Secure renegotiation support in TLS 1.3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_RENEGOTIATION)
#error "Renegotiation is not supported in TLS 1.3"
#endif

 /* Session tickets in TLS 1.3 does not use RFC 5077 anymore
 * Hence, when TLS 1.3 is used then MBEDTLS_SSL_SESSION_TICKETS cannot be enabled.
 *
 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_SESSION_TICKETS)
#error "RFC 5077 is not supported with TLS 1.3"
#endif

 /* JPAKE extension does not work with TLS 1.3
 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_ECJPAKE_C)
#error " JPAKE extension does not work with TLS 1.3"
#endif


 /* The following C processor directives are not applicable to TLS 1.3
 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
#error "No ECDH-ECDSA ciphersuite available in TLS 1.3"
#endif


 /* The following functionality is not yet supported with this TLS 1.3 implementation.
 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && ( defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED))
#error "RSA-based ciphersuites not supported with this TLS 1.3 implementation"
#endif


#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK)
#error "DHE-PSK-based ciphersuites not supported with this TLS 1.3 implementation"
#endif

 /* Caching in TLS 1.3 works differently than in TLS 1.2
  * Hence, SSL Cache MUST NOT be enabled.
 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_CACHE_C)
#error "SSL Caching not supported with TLS 1.3"
#endif


#if  defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_NEW_SESSION_TICKET) && defined(MBEDTLS_SSL_SESSION_TICKETS)
#error "The new session ticket concept is only available with TLS 1.3 and is not compatible with RFC 5077-style session tickets."
#endif

 /* Either SHA-256 or SHA-512 must be enabled.
  *
  */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && ( !defined(MBEDTLS_SHA256_C) && !defined(MBEDTLS_SHA512_C) )
#error "With TLS 1.3 SHA-256 and/or SHA-384 must be enabled"
#endif

#if defined(MBEDTLS_SHA512_C) && defined(MBEDTLS_SSL_NEW_SESSION_TICKET) && (MBEDTLS_PSK_MAX_LEN==32)
#error "MBEDTLS_PSK_MAX_LEN needs to be set to 48 bytes"
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && !defined(MBEDTLS_HKDF_C)
#error "MBEDTLS_HKDF_C is required for TLS 1_3 to work. "
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP) && ( !defined(MBEDTLS_SSL_PROTO_DTLS) )
#error "MBEDTLS_SSL_DTLS_SRTP defined, but not all prerequisites"
#endif

/* Reject attempts to enable options that have been removed and that could
 * cause a build to succeed but with features removed. */

#if defined(MBEDTLS_HAVEGE_C) //no-check-names
#error "MBEDTLS_HAVEGE_C was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/2599"
#endif

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL) //no-check-names
#error "MBEDTLS_SSL_HW_RECORD_ACCEL was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4031"
#endif

#if defined(MBEDTLS_SSL_PROTO_SSL3) //no-check-names
#error "MBEDTLS_SSL_PROTO_SSL3 (SSL v3.0 support) was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4031"
#endif

#if defined(MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO) //no-check-names
#error "MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO (SSL v2 ClientHello support) was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4031"
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC_COMPAT) //no-check-names
#error "MBEDTLS_SSL_TRUNCATED_HMAC_COMPAT (compatibility with the buggy implementation of truncated HMAC in Mbed TLS up to 2.7) was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4031"
#endif

#if defined(MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES) //no-check-names
#error "MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES was removed in Mbed TLS 3.0. See the ChangeLog entry if you really need SHA-1-signed certificates."
#endif

#if defined(MBEDTLS_ZLIB_SUPPORT) //no-check-names
#error "MBEDTLS_ZLIB_SUPPORT was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4031"
#endif

#if defined(MBEDTLS_CHECK_PARAMS) //no-check-names
#error "MBEDTLS_CHECK_PARAMS was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4313"
#endif

#if defined(MBEDTLS_SSL_CID_PADDING_GRANULARITY) //no-check-names
#error "MBEDTLS_SSL_CID_PADDING_GRANULARITY was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4335"
#endif

#if defined(MBEDTLS_SSL_TLS1_3_PADDING_GRANULARITY) //no-check-names
#error "MBEDTLS_SSL_TLS1_3_PADDING_GRANULARITY was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4335"
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC) //no-check-names
#error "MBEDTLS_SSL_TRUNCATED_HMAC was removed in Mbed TLS 3.0. See https://github.com/ARMmbed/mbedtls/issues/4341"
#endif

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(MBEDTLS_xxx_C) that results in empty translation units.
 */
typedef int mbedtls_iso_c_forbids_empty_translation_units;

#endif /* MBEDTLS_CHECK_CONFIG_H */
