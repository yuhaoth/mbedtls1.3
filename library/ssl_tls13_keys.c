/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include "mbedtls/hkdf.h"
#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/*
 * This function creates a HkdfLabel structure used in the TLS 1.3 key schedule.
 *
 * The HkdfLabel is specified in RFC 8446 as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;            // Length of expanded key material
 *   opaque label<7..255>;     // Always prefixed by "tls13 "
 *   opaque context<0..255>;   // Usually a communication transcript hash
 * };
 *
 * Parameters:
 * - desired_length: Length of expanded key material
 *                   Even though the standard allows expansion to up to
 *                   2**16 Bytes, TLS 1.3 never uses expansion to more than
 *                   255 Bytes, so we require `desired_length` to be at most
 *                   255. This allows us to save a few Bytes of code by
 *                   hardcoding the writing of the high bytes.
 * - (label, llen): label + label length, without "tls13 " prefix
 *                  The label length MUST be
 *                  <= MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                  It is the caller's responsiblity to ensure this.
 * - (ctx, clen): context + context length
 *                The context length MUST be
 *                <= MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                It is the caller's responsiblity to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dlen: Pointer at which to store the actual length of
 *         the HkdfLabel structure on success.
 */

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN       \
      + 1                  /* context length             */ \
      + MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

#define _JOIN(x,y) x ## y
#define JOIN(x,y) _JOIN( x, y )
#define STATIC_ASSERT( const_expr )                                           \
    struct JOIN(_static_assert_struct, __LINE__) {                            \
        int JOIN(__static_assert_field, __LINE__) : 1 - 2 * ! ( const_expr ); \
    }

STATIC_ASSERT( SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN < 255 );

static void ssl_tls1_3_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t llen,
                            const unsigned char *ctx, size_t clen,
                            unsigned char *dst, size_t *dlen )
{
    const char label_prefix[6] = { 't', 'l', 's', '1', '3', ' ' };
    size_t total_label_len = sizeof( label_prefix ) + llen;
    size_t total_hkdf_lbl_len =
          2                  /* length of expanded key material */
        + 1                  /* label length                    */
        + total_label_len    /* actual label, incl. prefix      */
        + 1                  /* context length                  */
        + clen;              /* actual context                  */

    unsigned char *p = dst;

    /* Add total length. */
    *p++ = 0;
    *p++ = (unsigned char)( ( desired_length >> 0 ) & 0xFF );

    /* Add label incl. prefix */
    *p++ = (unsigned char)( total_label_len & 0xFF );
    memcpy( p, label_prefix, sizeof(label_prefix) );
    p += sizeof(label_prefix);
    memcpy( p, label, llen );
    p += llen;

    /* Add context value */
    *p++ = (unsigned char)( clen & 0xFF );
    if( ctx != NULL )
        memcpy( p, ctx, clen );

    /* Return total length to the caller.  */
    *dlen = total_hkdf_lbl_len;
}

/*
* The traffic keying material is generated from the following inputs:
*
*  - One secret value per sender.
*  - A purpose value indicating the specific value being generated
*  - The desired lengths of key and IV.
*
* The expansion itself is based on HKDF:
*
*   [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
*   [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
*
* [sender] denotes the sending side and the Secret value is provided
* by the function caller. Note that we generate server and client side
* keys in a single function call.
*/
int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t keyLen, size_t ivLen,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    keys->clientWriteKey = mbedtls_calloc( keyLen,1 );
    if( keys->clientWriteKey == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating clientWriteKey.\n" );
        return( ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_secret, slen, (const unsigned char *) "key", 3,
                          (const unsigned char *)"", 0,
                          keys->clientWriteKey, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for clientWriteKey %d.\n", ret );
        return( ( ret ) );
    }

    keys->serverWriteKey = mbedtls_calloc( keyLen,1 );
    if( keys->serverWriteKey == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating serverWriteKey.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_secret, slen, (const unsigned char *)"key", 3,
                          (const unsigned char *)"", 0,
                          keys->serverWriteKey, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for serverWriteKey %d.\n", ret );
        return( ( ret ) );
    }

    // Compute clientWriteIV
    keys->clientWriteIV = mbedtls_calloc( ivLen,1 );
    if( keys->clientWriteIV == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating clientWriteIV.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_secret, slen, (const unsigned char *) "iv", 2,
                          (const unsigned char *)"", 0,
                          keys->clientWriteIV, ivLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for clientWriteIV %d.\n", ret );
        return( ( ret ) );
    }

    // Compute serverWriteIV
    keys->serverWriteIV = mbedtls_calloc( ivLen,1 );
    if( keys->serverWriteIV == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating serverWriteIV.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_secret, slen, (const unsigned char *) "iv", 2,
                          (const unsigned char *)"", 0,
                          keys->serverWriteIV, ivLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for serverWriteIV %d.\n", ret );
        return( ( ret ) );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)

    // Compute client_sn_key
    keys->client_sn_key = mbedtls_calloc( keyLen, 1 );
    if( keys->client_sn_key == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating client_sn_key.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_secret, slen, (const unsigned char *) "sn", 2,
                          (const unsigned char *)"", 0,
                          keys->client_sn_key, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for client_sn_key %d.\n", ret );
        return( ( ret ) );
    }

    // Compute server_sn_key
    keys->server_sn_key = mbedtls_calloc( keyLen, 1 );
    if( keys->server_sn_key == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating server_sn_key.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_secret, slen, (const unsigned char *) "sn", 2,
                          (const unsigned char *)"", 0,
                          keys->server_sn_key, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for server_sn_key %d.\n", ret );
        return( ( ret ) );
    }

#endif /* MBEDTLS_SSL_PROTO_DTLS */


    // Set epoch value to "undefined"
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    keys->epoch = -1;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    // Set key length
    // Set IV length
    keys->keyLen = keyLen;
    keys->ivLen = ivLen;
    return( 0 );
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen )
{
    const mbedtls_md_info_t *md;
    unsigned char hkdf_label[ SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN ];
    size_t hkdf_label_len;

    if( llen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN )
    {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( clen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( blen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl_tls1_3_hkdf_encode_label( blen,
                                  label, llen,
                                  ctx, clen,
                                  hkdf_label,
                                  &hkdf_label_len );

    return( mbedtls_hkdf_expand( md,
                                 secret, slen,
                                 hkdf_label, hkdf_label_len,
                                 buf, blen ) );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
