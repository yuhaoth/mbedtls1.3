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

/* Key Derivation for TLS 1.3
 *
 * Three tasks:
 *   - Switch transform for inbound data
 *   - Generate master key
 *   - Generate handshake traffic keys
 */
int mbedtls_ssl_handshake_key_derivation( mbedtls_ssl_context *ssl, mbedtls_ssl_key_set *traffic_keys )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_handshake_key_derivation" ) );

    /* Creating the Master Secret */
    if( ( ret = mbedtls_ssl_tls1_3_derive_master_secret( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_master_secret", ret );
        return( ret );
    }

    /* Creating the handshake traffic keys */
    if( ( ret = mbedtls_ssl_generate_handshake_traffic_keys( ssl, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_generate_handshake_traffic_keys", ret );
        return( ret );
    }

#if !defined(MBEDTLS_SSL_USE_MPS)
    /*
     * Set the in_msg pointer to the correct location based on IV length
     * For TLS 1.3 the record layer header has changed and hence we need to accomodate for it.
     */
    ssl->in_msg = ssl->in_iv;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_handshake_key_derivation" ) );
    return( 0 );
}

#if defined(MBEDTLS_SHA256_C)
static int ssl_calc_finished_tls_sha256(
    mbedtls_ssl_context* ssl, unsigned char* buf, int from )
{
    int ret;
    mbedtls_sha256_context sha256;
    unsigned char transcript[32];
    unsigned char* finished_key;
    const mbedtls_md_info_t* md;

    md = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );

    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "mbedtls_md_info_from_type failed" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mbedtls_sha256_init( &sha256 );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc finished tls sha256" ) );

    mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

    if( ( ret = mbedtls_sha256_finish_ret( &sha256, transcript ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "handshake hash", transcript, 32 );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key, Hash(
     *         Handshake Context +
     *         Certificate* +
     *         CertificateVerify* )
     *    )
     *
     *   * Only included if present.
     */


    /*
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     *
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    /* create client finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA256,
                          ssl->handshake->client_handshake_traffic_secret, 32,
                          MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                          NULL, 0,
                          ssl->handshake->client_finished_key, 32 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the client_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "client_finished_key", ssl->handshake->client_finished_key, 32 );

    /* create server finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA256,
                           ssl->handshake->server_handshake_traffic_secret, 32,
                           MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                           NULL, 0,
                           ssl->handshake->server_finished_key, 32 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the server_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "server_finished_key", ssl->handshake->server_finished_key, 32 );

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        /* In this case the server is receiving a finished message
         * sent by the client. It therefore needs to use the client_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using client_finished_key to compute mac ( for creating finished message )" ) );
        finished_key = ssl->handshake->client_finished_key;
    }
    else
    {
        /* If the server is sending a finished message then it needs to use
         * the server_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using server_finished_key to compute mac ( for verification procedure )" ) );
        finished_key = ssl->handshake->server_finished_key;
    }

    /* compute mac and write it into the buffer */
    ret = mbedtls_md_hmac( md, finished_key, 32, transcript, 32, buf );

    ssl->handshake->state_local.finished_out.digest_len = 32;

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_md_hmac", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "verify_data of Finished message" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Input", transcript, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Key", finished_key, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Output", buf, 32 );

exit:
    mbedtls_sha256_free( &sha256 );
    mbedtls_platform_zeroize( transcript, sizeof( transcript ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
    return ( ret );
}
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
static int ssl_calc_finished_tls_sha384(
    mbedtls_ssl_context* ssl, unsigned char* buf, int from )
{
    mbedtls_sha512_context sha512;
    int ret;
    unsigned char padbuf[48];
    unsigned char* finished_key;
    const mbedtls_md_info_t* md;

    md = mbedtls_md_info_from_type( MBEDTLS_MD_SHA384 );

    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "mbedtls_md_info_from_type failed" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }


    mbedtls_sha512_init( &sha512 );

    if( ( ret = mbedtls_sha512_starts_ret( &sha512, 1 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc finished tls sha384" ) );

    mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key, Hash(
     *         Handshake Context +
     *         Certificate* +
     *         CertificateVerify*
     *         )
     *    )
     *
     *   * Only included if present.
     */

    /*#if !defined(MBEDTLS_SHA512_ALT)
      MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha512 state", ( unsigned char * )
      sha512.state, sizeof( sha512.state ) );
      #endif
    */

    if( ( ret = mbedtls_sha512_finish_ret( &sha512, padbuf ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "handshake hash", padbuf, 48 );

    /* create client finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA384,
                      ssl->handshake->client_handshake_traffic_secret, 48,
                      MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                      NULL, 0,
                      ssl->handshake->client_finished_key, 48 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the client_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "client_finished_key", ssl->handshake->client_finished_key, 48 );

    /* create server finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA384,
                          ssl->handshake->server_handshake_traffic_secret, 48,
                          MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                          NULL, 0,
                          ssl->handshake->server_finished_key, 48 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the server_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "server_finished_key", ssl->handshake->server_finished_key, 48 );


    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        /* In this case the server is receiving a finished message
         * sent by the client. It therefore needs to use the client_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Using client_finished_key to compute mac ( for creating finished message )" ) );
        finished_key = ssl->handshake->client_finished_key;
    }
    else
    {
        /* If the server is sending a finished message then it needs to use
         * the server_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Using server_finished_key to compute mac ( for verification procedure )" ) );
        finished_key = ssl->handshake->server_finished_key;
    }

    /* compute mac and write it into the buffer */
    ret = mbedtls_md_hmac( md, finished_key, 48, padbuf, 48, buf );

    ssl->handshake->state_local.finished_out.digest_len = 48;

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "mbedtls_md_hmac", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "verify_data of Finished message" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Input", padbuf, 48 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Key", finished_key, 48 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Output", buf, 48 );

exit:
    mbedtls_sha512_free( &sha512 );

    mbedtls_platform_zeroize( padbuf, sizeof( padbuf ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
    return( 0 );
}
#endif /* MBEDTLS_SHA512_C */

/* mbedtls_ssl_generate_handshake_traffic_keys() generates keys necessary for
 * protecting the handshake messages, as described in Section 7 of TLS 1.3. */
int mbedtls_ssl_generate_handshake_traffic_keys( mbedtls_ssl_context *ssl,
                                                 mbedtls_ssl_key_set *traffic_keys )
{
    int ret = 0;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t keylen, ivlen;

#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context sha256;
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context sha512;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_generate_handshake_traffic_keys" ) );

    cipher_info = mbedtls_cipher_info_from_type(
                                  handshake->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                                    handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = mbedtls_md_info_from_type( handshake->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                                    handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    suite_info = mbedtls_ssl_ciphersuite_from_id(
                                  ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
#if defined(MBEDTLS_SHA256_C)
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
#else
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_SHA256_C */
    }

    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
#if defined(MBEDTLS_SHA512_C)
        handshake->calc_finished = ssl_calc_finished_tls_sha384;
#else
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_SHA512_C */
    }

    if( ( mbedtls_hash_size_for_ciphersuite( suite_info ) != 32 ) &&
        ( mbedtls_hash_size_for_ciphersuite( suite_info ) != 48 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        if( ( ret = mbedtls_sha256_finish_ret( &sha256, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "rolling hash", hash,
                 mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     *
     * Handshake Secret
     * |
     * +-----> Derive-Secret( ., "c hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = client_handshake_traffic_secret
     * |
     * +-----> Derive-Secret( ., "s hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = server_handshake_traffic_secret
     *
     */


    /*
     * Compute client_handshake_traffic_secret with
     *	 Derive-Secret( ., "c hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
             (const unsigned char*) ssl->handshake->handshake_secret,
             (int) mbedtls_hash_size_for_ciphersuite( suite_info ),
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_hs_traffic ),
             (const unsigned char * ) hash,
             (int) mbedtls_hash_size_for_ciphersuite( suite_info ),
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             (unsigned char *) ssl->handshake->client_handshake_traffic_secret,
             (int) mbedtls_hash_size_for_ciphersuite( suite_info ) );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        goto exit;
    }

    /*
     * Export client handshake traffic secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                ssl->handshake->client_handshake_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client handshake traffic secret",
                           ssl->handshake->client_handshake_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Compute server_handshake_traffic_secret with
     *   Derive-Secret( ., "s hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->handshake_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_hs_traffic ),
                         hash, mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->server_handshake_traffic_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );
    if( ret != 0 )
        goto exit;

    /*
     * Export server handshake traffic secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET,
                ssl->handshake->server_handshake_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server handshake traffic secret",
                           ssl->handshake->server_handshake_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Compute exporter_secret with
     *   mbedtls_ssl_tls1_3_derive_secret( Master Secret,
     *                                     "exp master",
     *                                     ClientHello...Server Finished )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( exp_master ),
                         hash, mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->exporter_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );
    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 4, "Exporter secret",
                           ssl->handshake->exporter_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Export exporter master secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_EXPORTER_MASTER_SECRET,
                ssl->handshake->exporter_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 5, "exporter_secret",
                           ssl->handshake->exporter_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    if( ( ret = mbedtls_ssl_tls1_3_make_traffic_keys( mbedtls_md_get_type( md_info ),
                                 ssl->handshake->client_handshake_traffic_secret,
                                 ssl->handshake->server_handshake_traffic_secret,
                                 mbedtls_hash_size_for_ciphersuite( suite_info ),
                                 keylen, ivlen, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_key",
                           traffic_keys->client_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_key",
                           traffic_keys->server_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_iv",
                           traffic_keys->client_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_iv",
                           traffic_keys->server_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= derive traffic keys" ) );

exit:
#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_free( &sha256 );
    }
    else
#endif
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_free( &sha512 );
    }
    else
#endif
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( ret );
}

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
/* Generate resumption_master_secret for use with the ticket exchange. */
int mbedtls_ssl_generate_resumption_master_secret( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    const mbedtls_md_info_t *md_info;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context sha512;
#endif

    suite_info = ssl->handshake->ciphersuite_info;

    md_info = mbedtls_md_info_from_type( suite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                                    ssl->handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        if( ( ret = mbedtls_sha256_finish_ret( &sha256, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        /* Should never happen */
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Compute resumption_master_secret with
     *   mbedtls_ssl_tls1_3_derive_secret( Master Secret,
     *                                     "res master",
     *                                     ClientHello...client Finished )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_master ),
                         hash, mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->session_negotiate->resumption_master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );

    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 5, "resumption_master_secret",
                           ssl->session_negotiate->resumption_master_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );


exit:
#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_free( &sha256 );
    }
    else
#endif
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_free( &sha512 );
    }
    else
#endif
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( ret );
}
#else /* MBEDTLS_SSL_NEW_SESSION_TICKET */
int mbedtls_ssl_generate_resumption_master_secret( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( 0 );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */


#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/* mbedtls_ssl_create_binder():
 *
 *                0
 *                |
 *                v
 *   PSK ->  HKDF-Extract = Early Secret
 *                |
 *                +------> Derive-Secret( .,
 *                |                      "ext binder" |
 *                |                      "res binder",
 *                |                      "" )
 *                |                     = binder_key
 *                |
 *                +-----> Derive-Secret( ., "c e traffic",
 *                |                     ClientHello )
 *                |                     = client_early_traffic_secret
 *               ...
 */

int mbedtls_ssl_create_binder( mbedtls_ssl_context *ssl,
                               int is_external,
                               unsigned char *psk, size_t psk_len,
                               const mbedtls_md_info_t *md,
                               const mbedtls_ssl_ciphersuite_t *suite_info,
                               unsigned char *result )
{
    int ret = 0;
    int hash_length;
    unsigned char salt[MBEDTLS_MD_MAX_SIZE];
    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;
    unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char finished_key[MBEDTLS_MD_MAX_SIZE];

    hash_length = mbedtls_hash_size_for_ciphersuite( suite_info );
    if( hash_length == -1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Compute Early Secret with HKDF-Extract( 0, PSK )
     */
    memset( salt, 0x0, hash_length );
    ret = mbedtls_hkdf_extract( md, salt, hash_length,
                                psk, psk_len,
                                ssl->handshake->early_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_hkdf_extract", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "HKDF Extract -- early_secret" ) );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Salt", salt, hash_length );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Input", psk, psk_len );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Output", ssl->handshake->early_secret,
                           hash_length );

    /*
     * Compute binder_key with
     *
     *    Derive-Secret( early_secret, "ext binder" | "res binder", "" )
     */

    if( !is_external )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md ),
                            ssl->handshake->early_secret, hash_length,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, hash_length );
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Derive Early Secret with 'res binder'" ) );
    }
    else
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md ),
                            ssl->handshake->early_secret, hash_length,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( ext_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, hash_length );
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Derive Early Secret with 'ext binder'" ) );
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        return( ret );
    }

    /* Get current state of handshake transcript. */
    ret = mbedtls_ssl_get_handshake_transcript( ssl, suite_info->mac,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
        return( ret );

    /*
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     *
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( suite_info->mac, binder_key,
                            hash_length,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                            NULL, 0,
                            finished_key, hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "finished_key", finished_key, hash_length );

    /* compute mac and write it into the buffer */
    ret = mbedtls_md_hmac( md, finished_key, hash_length,
                           transcript, transcript_len,
                           result );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_md_hmac", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "verify_data of psk binder" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Input", transcript, hash_length );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Key", finished_key, hash_length );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Output", result, hash_length );

exit:

    mbedtls_platform_zeroize( finished_key, sizeof( finished_key ) );
    mbedtls_platform_zeroize( binder_key,   sizeof( binder_key ) );
    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
