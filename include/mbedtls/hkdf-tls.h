/**
* \file hkdf-tls.h
*
* \brief TLS 1.3-specific HKDF functionality
*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*/
#ifndef MBEDTLS_HKDF_TLS_H
#define MBEDTLS_HKDF_TLS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

//#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

//#include "sha_new.h"

#define MBEDTLS_ERR_HKDF_BUFFER_TOO_SMALL                  -0x6A00  /**< A buffer is too small to store label */
//#define MBEDTLS_ERR_HKDF_BAD_INPUT_DATA                    -0x7100  /**< Bad input parameters to function.  */
#define MBEDTLS_ERR_HKDF_ALLOC_FAILED                      -0x4D80  /**< Memory allocation failed. */

#ifdef __cplusplus
extern "C" {
#endif



/**
 * \brief           hkdfEncodeLabel creates the HkdfLabel structure.
 *
 * \param label     Label Text
 * \param llen      Label Length 
 * \param hashValue Hash Value
 * \param hlen      Length of hash value 
 * \param buf		Output buffer 
 * \param length    Length is a value encoded in the HkdfLabel structure.
 *
 * \return          0 if successful,
 *                  or MBEDTLS_ERR_HKDF_BUFFER_TOO_SMALL
 *
 * \note            TLS 1.3 encodes the labels for the HKDF function
 *                  in a unique way. This function allows to 
 *                  conveniently create these labels. 
 * 
 *                  The function assumes that enough buffer has been 
 *                  allocated in buf to hold the result. 
 */
int hkdfEncodeLabel(const unsigned char *label, int llen,
                    const unsigned char *hashValue, int hlen,
                    unsigned char *buf, int length);

/**
 * \brief   Derive_Secret() implements the TLS 1.3 Derive-Secret() function.
 *                  
 * Derive-Secret(Secret, Label, Messages) =
 *   HKDF-Expand-Label(Secret, Label,
 *    Hash(Messages), Hash.Length))
 * 
 * Note: In this implementation of the function we assume that
 * the parameter message contains the already hashed value and
 * the Derive-Secret function does not need to hash it again.
 *
 * \param ssl     mbedtls_ssl_context 
 * \param secret  Secret key
 * \param slen    Length of secret
 * \param label   Label
 * \param llen    Length of label
 * \param message TLS messages to hash
 * \param mlen    Length of message
 * \param dstbuf  Buffer to write to
 * \param buflen  Buffer length
 *
 * \return          0 if successful,
 *                  or MBEDTLS_ERR_HKDF_BUFFER_TOO_SMALL
 *                  or MBEDTLS_ERR_HKDF_BAD_INPUT_DATA
 *                  or MBEDTLS_ERR_HKDF_ALLOC_FAILED
 */

int Derive_Secret(mbedtls_ssl_context *ssl, mbedtls_md_type_t hash_alg, const unsigned char *secret, int slen,
                  const unsigned char *label, int llen,
                  const unsigned char *message, int mlen,
                  unsigned char *dstbuf, int buflen);

/**
* \brief           makeTrafficKeys generates keys/IVs 
*                  for record layer encryption.
*
* \param hash_alg        Hash algorithm
* \param client_key      Label Length
* \param server_key Hash Value
* \param slen      Length of hash value
* \param keyLen	  Length of the key
* \param ivLen    Length of IV
* \param keys     KeySet structure containing client/server key and IVs
*
* \return          0 if successful,
*                  or MBEDTLS_ERR_HKDF_BUFFER_TOO_SMALL
*                  or MBEDTLS_ERR_HKDF_BAD_INPUT_DATA
*                  or MBEDTLS_ERR_HKDF_ALLOC_FAILED
*
*/ 

int makeTrafficKeys(mbedtls_md_type_t hash_alg,
	                const unsigned char *client_key,
	                const unsigned char *server_key,
	                int slen, int keyLen, int ivLen, KeySet *keys);

/**
* \brief           HKDF-Expand-Label(Secret, Label, HashValue, Length) =
*                       HKDF-Expand(Secret, HkdfLabel, Length). 
* 
*                  hkdfExpandLabel() uses hkdfEncodeLabel() to create the 
*                  HkdfLabel structure.  
*
* \param hash_alg  Hash algorithm
* \param secret    Secret key
* \param slen      Secret key length
* \param label     Label
* \param llen      Label length
* \param hashValue Hash value
* \param hlen      Hash value length
* \param length    Length (must be <= blen)
* \param buf       Output buffer
* \param blen      Output buffer length
*
* \return          0 if successful,
*                  or MBEDTLS_ERR_HKDF_BAD_PARAM
*                  or MBEDTLS_ERR_MD_BAD_INPUT_DATA
*                  or MBEDTLS_ERR_MD_ALLOC_FAILED
*/

int hkdfExpandLabel(mbedtls_md_type_t  hash_alg, const unsigned char *secret,
                    int slen, const unsigned char *label, int llen,
                    const unsigned char *hashValue, int hlen, int length,
                    unsigned char *buf, int blen);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HKDF_TLS_H */
