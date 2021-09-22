/*
 *  TLS 1.3 functionality shared between client and server
 *
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

#include "common.h"

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include <string.h>

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "mbedtls/platform.h"

int mbedtls_ssl_tls1_3_fetch_handshake_msg( mbedtls_ssl_context *ssl,
                                            unsigned hs_type,
                                            unsigned char **buf,
                                            size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0]  != hs_type )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Receive unexpected handshake message." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    /*
     * Jump handshake header (4 bytes, see Section 4 of RFC 8446).
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

cleanup:

    return( ret );
}

int mbedtls_ssl_tls13_start_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
{
    /*
     * Reserve 4 bytes for hanshake header. ( Section 4,RFC 8446 )
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf = ssl->out_msg + 4;
    *buf_len = MBEDTLS_SSL_OUT_CONTENT_LEN - 4;

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = hs_type;

    return( 0 );
}

int mbedtls_ssl_tls13_finish_handshake_msg( mbedtls_ssl_context *ssl,
                                            size_t buf_len,
                                            size_t msg_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t msg_len_with_header;
    ((void) buf_len);

    /* Add reserved 4 bytes for handshake header */
    msg_len_with_header = msg_len + 4;
    ssl->out_msglen = msg_len_with_header;
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg_ext( ssl, 0 ) );

cleanup:
    return( ret );
}

void mbedtls_ssl_tls1_3_add_hs_msg_to_checksum( mbedtls_ssl_context *ssl,
                                                unsigned hs_type,
                                                unsigned char const *msg,
                                                size_t msg_len )
{
    mbedtls_ssl_tls13_add_hs_hdr_to_checksum( ssl, hs_type, msg_len );
    ssl->handshake->update_checksum( ssl, msg, msg_len );
}

void mbedtls_ssl_tls13_add_hs_hdr_to_checksum( mbedtls_ssl_context *ssl,
                                               unsigned hs_type,
                                               size_t total_hs_len )
{
    unsigned char hs_hdr[4];

    /* Build HS header for checksum update. */
    hs_hdr[0] = MBEDTLS_BYTE_0( hs_type );
    hs_hdr[1] = MBEDTLS_BYTE_2( total_hs_len );
    hs_hdr[2] = MBEDTLS_BYTE_1( total_hs_len );
    hs_hdr[3] = MBEDTLS_BYTE_0( total_hs_len );

    ssl->handshake->update_checksum( ssl, hs_hdr, sizeof( hs_hdr ) );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/*
 * mbedtls_ssl_tls13_write_sig_alg_ext( )
 *
 * enum {
 *    ....
 *   ecdsa_secp256r1_sha256( 0x0403 ),
 *   ecdsa_secp384r1_sha384( 0x0503 ),
 *   ecdsa_secp521r1_sha512( 0x0603 ),
 *    ....
 * } SignatureScheme;
 *
 * struct {
 *    SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 *
 * Only if we handle at least one key exchange that needs signatures.
 */
int mbedtls_ssl_tls13_write_sig_alg_ext( mbedtls_ssl_context *ssl,
                                         unsigned char *buf,
                                         unsigned char *end,
                                         size_t *olen )
{
    unsigned char *p = buf;
    unsigned char *supported_sig_alg_ptr; /* Start of supported_signature_algorithms */
    size_t supported_sig_alg_len = 0;     /* Length of supported_signature_algorithms */

    *olen = 0;

    /* Skip the extension on the client if all allowed key exchanges
     * are PSK-based. */
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
    {
        return( 0 );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding signature_algorithms extension" ) );

    /* Check if we have space for header and length field:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - supported_signature_algorithms_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    /*
     * Write supported_signature_algorithms
     */
    supported_sig_alg_ptr = p;
    for( const uint16_t *sig_alg = ssl->conf->tls13_sig_algs;
         *sig_alg != MBEDTLS_TLS13_SIG_NONE; sig_alg++ )
    {
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( *sig_alg, p, 0 );
        p += 2;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "signature scheme [%x]", *sig_alg ) );
    }

    /* Length of supported_signature_algorithms */
    supported_sig_alg_len = p - supported_sig_alg_ptr;
    if( supported_sig_alg_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No signature algorithms defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SIG_ALG, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( supported_sig_alg_len + 2, buf, 2 );
    /* Write length of supported_signature_algorithms */
    MBEDTLS_PUT_UINT16_BE( supported_sig_alg_len, buf, 4 );

    /* Output the total length of signature algorithms extension. */
    *olen = p - buf;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIG_ALG;
    return( 0 );
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 *
 * STATE HANDLING: Incoming Finished
 *
 */

/*
 * Overview
 */

/* Main entry point: orchestrates the other functions */
int mbedtls_ssl_tls1_3_finished_in_process( mbedtls_ssl_context* ssl );

static int ssl_finished_in_preprocess( mbedtls_ssl_context* ssl );
static int ssl_finished_in_postprocess( mbedtls_ssl_context* ssl );
static int ssl_finished_in_parse( mbedtls_ssl_context* ssl,
                                  const unsigned char* buf,
                                  size_t buflen );

/*
 * Implementation
 */

int mbedtls_ssl_tls1_3_finished_in_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buflen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse finished" ) );

    /* Preprocessing step: Compute handshake digest */
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_preprocess( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls1_3_fetch_handshake_msg( ssl,
                                              MBEDTLS_SSL_HS_FINISHED,
                                              &buf, &buflen ) );
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_parse( ssl, buf, buflen ) );
    mbedtls_ssl_tls1_3_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_FINISHED, buf, buflen );
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse finished" ) );
    return( ret );
}

static int ssl_finished_in_preprocess( mbedtls_ssl_context* ssl )
{
    int ret;

    ret = mbedtls_ssl_tls1_3_calc_finished( ssl,
                    ssl->handshake->state_local.finished_in.digest,
                    sizeof( ssl->handshake->state_local.finished_in.digest ),
                    &ssl->handshake->state_local.finished_in.digest_len,
                    ssl->conf->endpoint ^ 1 );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_calc_finished", ret );
        return( ret );
    }

    return( 0 );
}

static int ssl_finished_in_parse( mbedtls_ssl_context* ssl,
                                  const unsigned char* buf,
                                  size_t buflen )
{
    /* Structural validation */
    if( buflen != ssl->handshake->state_local.finished_in.digest_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Hash (self-computed):",
                           ssl->handshake->state_local.finished_in.digest,
                           ssl->handshake->state_local.finished_in.digest_len );
    MBEDTLS_SSL_DEBUG_BUF( 4, "Hash (received message):", buf,
                           ssl->handshake->state_local.finished_in.digest_len );

    /* Semantic validation */
    if( mbedtls_ssl_safer_memcmp( buf,
                   ssl->handshake->state_local.finished_in.digest,
                   ssl->handshake->state_local.finished_in.digest_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( 0 );
}

static int ssl_finished_in_postprocess_cli( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    mbedtls_ssl_key_set traffic_keys;
    mbedtls_ssl_transform *transform_application;

    ret = mbedtls_ssl_tls1_3_key_schedule_stage_application( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
           "mbedtls_ssl_tls1_3_key_schedule_stage_application", ret );
        return( ret );
    }

    ret = mbedtls_ssl_tls1_3_generate_application_keys(
        ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
            "mbedtls_ssl_tls1_3_generate_application_keys", ret );
        return( ret );
    }

    transform_application =
        mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_application == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    ret = mbedtls_ssl_tls13_populate_transform(
                                    transform_application,
                                    ssl->conf->endpoint,
                                    ssl->session_negotiate->ciphersuite,
                                    &traffic_keys,
                                    ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        return( ret );
    }

    ssl->transform_application = transform_application;

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_END_OF_EARLY_DATA );
    return( 0 );
}

static int ssl_finished_in_postprocess( mbedtls_ssl_context* ssl )
{

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        return( ssl_finished_in_postprocess_cli( ssl ) );
    }

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

/*
 *
 * STATE HANDLING: Outgoing Finished
 *
 */

/*
 * Overview
 */

/* Main entry point: orchestrates the other functions */

int mbedtls_ssl_finished_out_process( mbedtls_ssl_context *ssl );

static int ssl_finished_out_prepare( mbedtls_ssl_context *ssl );
static int ssl_finished_out_write( mbedtls_ssl_context *ssl,
                                   unsigned char *buf,
                                   size_t buflen,
                                   size_t *olen );
static int ssl_finished_out_postprocess( mbedtls_ssl_context *ssl );


int mbedtls_ssl_tls1_3_finished_out_process( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write finished" ) );

    if( !ssl->handshake->state_local.finished_out.preparation_done )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_finished_out_prepare( ssl ) );
        ssl->handshake->state_local.finished_out.preparation_done = 1;
    }

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg( ssl,
                         MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_finished_out_write(
                              ssl, buf, buf_len, &msg_len ) );

    mbedtls_ssl_tls1_3_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_FINISHED,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( ssl_finished_out_postprocess( ssl ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg( ssl,
                                              buf_len, msg_len ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write finished" ) );
    return( ret );
}

static int ssl_finished_out_prepare( mbedtls_ssl_context *ssl )
{
    int ret;

    /* Compute transcript of handshake up to now. */
    ret = mbedtls_ssl_tls1_3_calc_finished( ssl,
                    ssl->handshake->state_local.finished_out.digest,
                    sizeof( ssl->handshake->state_local.finished_out.digest ),
                    &ssl->handshake->state_local.finished_out.digest_len,
                    ssl->conf->endpoint );

    if( ret != 0 )
    {
         MBEDTLS_SSL_DEBUG_RET( 1, "calc_finished failed", ret );
        return( ret );
    }

    return( 0 );
}

static int ssl_finished_out_postprocess( mbedtls_ssl_context *ssl )
{
    int ret = 0;

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        /* Compute resumption_master_secret */
        ret = mbedtls_ssl_tls1_3_generate_resumption_master_secret( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                    "mbedtls_ssl_tls1_3_generate_resumption_master_secret ", ret );
            return ( ret );
        }

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_FLUSH_BUFFERS );
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( 0 );
}

static int ssl_finished_out_write( mbedtls_ssl_context *ssl,
                                   unsigned char *buf,
                                   size_t buflen,
                                   size_t *olen )
{
    size_t finished_len = ssl->handshake->state_local.finished_out.digest_len;

    /* Note: Even if DTLS is used, the current message writing functions
     * write TLS headers, and it is only at sending time that the actual
     * DTLS header is generated. That's why we unconditionally shift by
     * 4 bytes here as opposed to mbedtls_ssl_hs_hdr_len( ssl ). */

    if( buflen < finished_len )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    memcpy( buf, ssl->handshake->state_local.finished_out.digest,
            ssl->handshake->state_local.finished_out.digest_len );

    *olen = finished_len;
    return( 0 );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS_C */
