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
 */

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/hkdf.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/debug.h"
#include "ssl_tls13_keys.h"

#include <stdint.h>
#include <string.h>

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    .name = string,

struct mbedtls_ssl_tls1_3_labels_struct const mbedtls_ssl_tls1_3_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};

#undef MBEDTLS_SSL_TLS1_3_LABEL

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
 *                  The label length MUST be less than or equal to
 *                  MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                  It is the caller's responsibility to ensure this.
 *                  All (label, label length) pairs used in TLS 1.3
 *                  can be obtained via MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN().
 * - (ctx, clen): context + context length
 *                The context length MUST be less than or equal to
 *                MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                It is the caller's responsibility to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dlen: Pointer at which to store the actual length of
 *         the HkdfLabel structure on success.
 */

static const char tls1_3_label_prefix[6] = "tls13 ";

#define SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( label_len, context_len ) \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + label_len                                           \
      + 1                  /* context length             */ \
      + context_len )

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
                     sizeof(tls1_3_label_prefix) +                      \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN,     \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

static void ssl_tls1_3_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t llen,
                            const unsigned char *ctx, size_t clen,
                            unsigned char *dst, size_t *dlen )
{
    size_t total_label_len =
        sizeof(tls1_3_label_prefix) + llen;
    size_t total_hkdf_lbl_len =
        SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( total_label_len, clen );

    unsigned char *p = dst;

    /* Add the size of the expanded key material.
     * We're hardcoding the high byte to 0 here assuming that we never use
     * TLS 1.3 HKDF key expansion to more than 255 Bytes. */
#if MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN > 255
#error "The implementation of ssl_tls1_3_hkdf_encode_label() is not fit for the \
        value of MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN"
#endif

    *p++ = 0;
    *p++ = (unsigned char)( ( desired_length >> 0 ) & 0xFF );

    /* Add label incl. prefix */
    *p++ = (unsigned char)( total_label_len & 0xFF );
    memcpy( p, tls1_3_label_prefix, sizeof(tls1_3_label_prefix) );
    p += sizeof(tls1_3_label_prefix);
    memcpy( p, label, llen );
    p += llen;

    /* Add context value */
    *p++ = (unsigned char)( clen & 0xFF );
    if( clen != 0 )
        memcpy( p, ctx, clen );

    /* Return total length to the caller.  */
    *dlen = total_hkdf_lbl_len;
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
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->client_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->server_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->client_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->server_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    keys->key_len = key_len;
    keys->iv_len = iv_len;

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t buflen )
{
    int ret;
    unsigned char hashed_context[ MBEDTLS_MD_MAX_SIZE ];

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ctx_hashed == MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED )
    {
        ret = mbedtls_md( md, ctx, clen, hashed_context );
        if( ret != 0 )
            return( ret );
        clen = mbedtls_md_get_size( md );
    }
    else
    {
        if( clen > sizeof(hashed_context) )
        {
            /* This should never happen since this function is internal
             * and the code sets `ctx_hashed` correctly.
             * Let's double-check nonetheless to not run at the risk
             * of getting a stack overflow. */
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( hashed_context, ctx, clen );
    }

    return( mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                                                  secret, slen,
                                                  label, llen,
                                                  hashed_context, clen,
                                                  dstbuf, buflen ) );
}

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new )
{
    int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    size_t hlen, ilen;
    unsigned char tmp_secret[ MBEDTLS_MD_MAX_SIZE ] = { 0 };
    unsigned char tmp_input [ MBEDTLS_SSL_TLS1_3_MAX_IKM_SIZE ] = { 0 };

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md );

    /* For non-initial runs, call Derive-Secret( ., "derived", "")
     * on the old secret. */
    if( secret_old != NULL )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret(
                   hash_alg,
                   secret_old, hlen,
                   MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( derived ),
                   NULL, 0, /* context */
                   MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                   tmp_secret, hlen );
        if( ret != 0 )
            goto cleanup;
    }

    if( input != NULL )
    {
        memcpy( tmp_input, input, input_len );
        ilen = input_len;
    }
    else
    {
        ilen = hlen;
    }

    /* HKDF-Extract takes a salt and input key material.
     * The salt is the old secret, and the input key material
     * is the input secret (PSK / ECDHE). */
    ret = mbedtls_hkdf_extract( md,
                    tmp_secret, hlen,
                    tmp_input, ilen,
                    secret_new );
    if( ret != 0 )
        goto cleanup;

    ret = 0;

 cleanup:

    mbedtls_platform_zeroize( tmp_secret, sizeof(tmp_secret) );
    mbedtls_platform_zeroize( tmp_input,  sizeof(tmp_input)  );
    return( ret );
}

/*
 *
 * The following code hasn't been upstreamed yet.
 *
 */

/* Generate application traffic keys since any records following a 1-RTT Finished message
 * MUST be encrypted under the application traffic key.
 */
int mbedtls_ssl_generate_application_traffic_keys(
                                        mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_key_set *traffic_keys )
{
    int ret;
    const mbedtls_md_info_t *md_info;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    const mbedtls_cipher_info_t *cipher_info;
    size_t keylen, ivlen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> derive application traffic keys" ) );

    cipher_info = mbedtls_cipher_info_from_type(
                              ssl->handshake->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                               ssl->handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = mbedtls_md_info_from_type( ssl->handshake->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                               ssl->handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );

    ivlen = cipher_info->iv_size;
    keylen = cipher_info->key_bitlen / 8;

    MBEDTLS_SSL_DEBUG_BUF( 4, "Transcript hash (including Server.Finished):",
                              ssl->handshake->server_finished_digest,
                              mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /* Generate client_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +-----> Derive-Secret( ., "c ap traffic",
     * |                     ClientHello...server Finished )
     * |                     = client_application_traffic_secret_0
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_ap_traffic ),
                         ssl->handshake->server_finished_digest,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->client_traffic_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client application traffic secret",
                           ssl->handshake->client_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Export client application traffic secret 0
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET_0,
                ssl->handshake->client_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    /* Generate server_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +---------> Derive-Secret( ., "s ap traffic",
     * |                         ClientHello...Server Finished )
     * |                         = server_application_traffic_secret_0
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_ap_traffic ),
                         ssl->handshake->server_finished_digest,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->server_traffic_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server application traffic secret",
                           ssl->handshake->server_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Export server application traffic secret 0
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET_0,
                ssl->handshake->server_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    /* Generate application traffic keys since any records following a
     * 1-RTT Finished message MUST be encrypted under the application
     * traffic key. */

    if( ( ret = mbedtls_ssl_tls1_3_make_traffic_keys( mbedtls_md_get_type( md_info ),
                              ssl->handshake->client_traffic_secret,
                              ssl->handshake->server_traffic_secret,
                              mbedtls_hash_size_for_ciphersuite( suite_info ),
                              keylen, ivlen, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys failed", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client application_write_key:",
                              traffic_keys->client_write_key, keylen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write key",
                              traffic_keys->server_write_key, keylen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "client application write IV",
                              traffic_keys->client_write_iv, ivlen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write IV",
                              traffic_keys->server_write_iv, ivlen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= derive application traffic keys" ) );

    return( 0 );
}

#if defined(MBEDTLS_ZERO_RTT)
/* Early Data Key Derivation for TLS 1.3 */
int mbedtls_ssl_generate_early_data_keys( mbedtls_ssl_context *ssl,
                                          mbedtls_ssl_key_set *traffic_keys )
{
    int ret;
    int hash_length;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md;
    unsigned char padbuf[MBEDTLS_MD_MAX_SIZE];
    size_t keylen, ivlen;

#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context sha512;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_generate_early_data_keys" ) );

    ciphersuite_info = ssl->handshake->ciphersuite_info;
    cipher_info = mbedtls_cipher_info_from_type( ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                                    ssl->handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md = mbedtls_md_info_from_type( ssl->handshake->ciphersuite_info->mac );
    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                                    ssl->handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    hash_length = mbedtls_hash_size_for_ciphersuite( ciphersuite_info );
    if( hash_length == -1 )
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl_dtls_replay_reset( ssl );
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_DTLS_ANTI_REPLAY */

    if( ciphersuite_info->mac == MBEDTLS_MD_SHA256 )
    {
#if defined(MBEDTLS_SHA256_C)
        mbedtls_sha256_init( &sha256 );

        if( ( ret = mbedtls_sha256_starts_ret( &sha256, 0 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_starts_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha256 state",
                               (unsigned char *) sha256.state,
                               sizeof( sha256.state ) );

        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        if( ( ret = mbedtls_sha256_finish_ret( &sha256, padbuf ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash", padbuf, 32 );
#else
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif
    }
    else if( ciphersuite_info->mac == MBEDTLS_MD_SHA384 )
    {
#if defined(MBEDTLS_SHA512_C)
        mbedtls_sha512_init( &sha512 );

        if( ( ret = mbedtls_sha512_starts_ret( &sha512, 1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha384 state",
                               (unsigned char *)sha512.state, 48 );

        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, padbuf ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash", padbuf, 48 );
#else
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif
    }
    else if( ciphersuite_info->mac == MBEDTLS_MD_SHA512 )
    {
#if defined(MBEDTLS_SHA512_C)
        mbedtls_sha512_init( &sha512 );

        if( ( ret = mbedtls_sha512_starts_ret( &sha512, 0 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha512state", ( unsigned char * )sha512.state, 64 );

        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, padbuf ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash for psk binder", padbuf, 64 );
    }
    else
    {
#else
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_tls1_3_derive_master_secret: Unknow hash function." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif
    }

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
     *            |                     = binder_key
     *            |
     *            +-----> Derive-Secret(., "c e traffic", ClientHello)
     *            |                     = client_early_traffic_secret
     *            |
     *            +-----> Derive-Secret(., "e exp master", ClientHello)
     *            |                     = early_exporter_master_secret
     *            v
     */

    /* Create client_early_traffic_secret */
    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md ),
                         ssl->handshake->early_secret, hash_length,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_e_traffic ),
                         padbuf, hash_length, MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->client_early_traffic_secret, hash_length );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        goto exit;
    }


    MBEDTLS_SSL_DEBUG_BUF( 4, "client_early_traffic_secret",
                           ssl->handshake->client_early_traffic_secret,
                           hash_length );

    MBEDTLS_SSL_DEBUG_MSG( 4, ( "mbedtls_ssl_tls1_3_derive_secret with 'c e traffic'" ) );


    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    if( ( ret = mbedtls_ssl_tls1_3_make_traffic_keys( mbedtls_md_get_type( md ),
                                 ssl->handshake->client_early_traffic_secret,
                                 ssl->handshake->client_early_traffic_secret,
                                 mbedtls_hash_size_for_ciphersuite( ciphersuite_info ),
                                 keylen, ivlen, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_generate_early_data_keys" ) );

exit:
#if defined(MBEDTLS_SHA256_C)
    if( ciphersuite_info->mac == MBEDTLS_MD_SHA256 )
    {
        mbedtls_sha256_free( &sha256 );
    }
    else
#endif
#if defined(MBEDTLS_SHA512_C)
    if( ciphersuite_info->mac == MBEDTLS_MD_SHA384 ||
        ciphersuite_info->mac == MBEDTLS_MD_SHA512 )
    {
        mbedtls_sha512_free( &sha512 );
    }
    else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_tls1_3_derive_master_secret: Unknow hash function." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( ret );
}
#endif /* MBEDTLS_ZERO_RTT */



#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
