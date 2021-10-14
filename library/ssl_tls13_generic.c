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

#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"

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

/*
 * The ssl_tls13_create_verify_structure() creates the verify structure.
 * As input, it requires the transcript hash.
 *
 * The caller has to ensure that the buffer has size at least
 * SSL_VERIFY_STRUCT_MAX_SIZE bytes.
 */
static void ssl_tls13_create_verify_structure( unsigned char *transcript_hash,
                                               size_t transcript_hash_len,
                                               unsigned char *verify_buffer,
                                               size_t *verify_buffer_len,
                                               int from )
{
    size_t idx = 0;

    /* RFC 8446, Section 4.4.3:
     *
     * The digital signature [in the CertificateVerify message] is then
     * computed over the concatenation of:
     * -  A string that consists of octet 32 (0x20) repeated 64 times
     * -  The context string
     * -  A single 0 byte which serves as the separator
     * -  The content to be signed
     */
    uint8_t const verify_padding_val = 0x20;
    size_t const verify_padding_len = 64;

    memset( verify_buffer + idx, verify_padding_val, verify_padding_len );
    idx += verify_padding_len;

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        memcpy( verify_buffer + idx, MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( client_cv ) );
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN( client_cv );
    }
    else
    { /* from == MBEDTLS_SSL_IS_SERVER */
        memcpy( verify_buffer + idx, MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( server_cv ) );
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN( server_cv );
    }

    verify_buffer[idx++] = 0x0;

    memcpy( verify_buffer + idx, transcript_hash, transcript_hash_len );
    idx += transcript_hash_len;

    *verify_buffer_len = idx;
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 * STATE HANDLING: Read CertificateVerify
 */
/* Macro to express the length of the verify structure length.
 *
 * The structure is computed per TLS 1.3 specification as:
 *   - 64 bytes of octet 32,
 *   - 33 bytes for the context string
 *        (which is either "TLS 1.3, client CertificateVerify"
 *         or "TLS 1.3, server CertificateVerify"),
 *   - 1 byte for the octet 0x0, which servers as a separator,
 *   - 32 or 48 bytes for the Transcript-Hash(Handshake Context, Certificate)
 *     (depending on the size of the transcript_hash)
 *
 * This results in a total size of
 * - 130 bytes for a SHA256-based transcript hash, or
 *   (64 + 33 + 1 + 32 bytes)
 * - 146 bytes for a SHA384-based transcript hash.
 *   (64 + 33 + 1 + 48 bytes)
 *
 */
#define SSL_VERIFY_STRUCT_MAX_SIZE  ( 64 +                 \
                                      33 +                 \
                                       1 +                 \
                                      MBEDTLS_MD_MAX_SIZE  \
                                    )
/* Coordinate: Check whether a certificate verify message is expected.
 * Returns a negative value on failure, and otherwise
 * - SSL_CERTIFICATE_VERIFY_SKIP
 * - SSL_CERTIFICATE_VERIFY_READ
 * to indicate if the CertificateVerify message should be present or not.
 */
#define SSL_CERTIFICATE_VERIFY_SKIP 0
#define SSL_CERTIFICATE_VERIFY_READ 1
static int ssl_tls13_process_certificate_verify_coordinate(
                                    mbedtls_ssl_context *ssl )
{
    if( mbedtls_ssl_tls1_3_some_psk_enabled( ssl ) )
        return( SSL_CERTIFICATE_VERIFY_SKIP );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( ssl->session_negotiate->peer_cert == NULL )
        return( SSL_CERTIFICATE_VERIFY_SKIP );
    return( SSL_CERTIFICATE_VERIFY_READ );
#else
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
static int ssl_tls13_process_certificate_verify_parse( mbedtls_ssl_context *ssl,
                                                       const unsigned char *buf,
                                                       const unsigned char *end,
                                                       const unsigned char *verify_buffer,
                                                       size_t verify_buffer_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t algorithm;
    const uint16_t *tls13_sig_alg = ssl->conf->tls13_sig_algs;
    size_t signature_len;
    mbedtls_pk_type_t sig_alg;
    mbedtls_md_type_t md_alg;
    unsigned char verify_hash[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t verify_hash_len;

    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    algorithm = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* RFC 8446 section 4.4.3
     *
     * If the CertificateVerify message is sent by a server, the signature algorithm
     * MUST be one offered in the client's "signature_algorithms" extension unless
     * no valid certificate chain can be produced without unsupported algorithms
     *
     * RFC 8446 section 4.4.2.2
     *
     * If the client cannot construct an acceptable chain using the provided
     * certificates and decides to abort the handshake, then it MUST abort the handshake
     * with an appropriate certificate-related alert (by default, "unsupported_certificate").
     *
     * Check if algorithm in offered signature algorithms. Send `unsupported_certificate`
     * alert message on failure.
     */
    while( 1 )
    {
        /* Found algorithm in offered signature algorithms */
        if( *tls13_sig_alg == algorithm )
            break;

        if( *tls13_sig_alg == MBEDTLS_TLS13_SIG_NONE )
        {
            /* End of offered signature algorithms list */
            MBEDTLS_SSL_DEBUG_MSG( 1,
                                   ( "signature algorithm(%04x) not in offered"
                                     "signature algorithms ",
                                     ( unsigned int ) algorithm ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }

        tls13_sig_alg++;
    }

    /* We currently only support ECDSA-based signatures */
    switch( algorithm )
    {
        case MBEDTLS_TLS13_SIG_ECDSA_SECP256R1_SHA256:
            md_alg = MBEDTLS_MD_SHA256;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        case MBEDTLS_TLS13_SIG_ECDSA_SECP384R1_SHA384:
            md_alg = MBEDTLS_MD_SHA384;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        case MBEDTLS_TLS13_SIG_ECDSA_SECP521R1_SHA512:
            md_alg = MBEDTLS_MD_SHA512;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Certificate Verify: Unknown signature algorithm." ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate Verify: Signature algorithm ( %04x )",
                                ( unsigned int ) algorithm ) );

    /*
     * Check the certificate's key type matches the signature alg
     */
    if( !mbedtls_pk_can_do( &ssl->session_negotiate->peer_cert->pk, sig_alg ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "signature algorithm doesn't match cert key" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
            MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    signature_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, signature_len );

    /* Hash verify buffer with indicated hash function */
    switch( md_alg )
    {
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA256:
            verify_hash_len = 32;
            if( ( ret = mbedtls_sha256( verify_buffer,
                                        verify_buffer_len,
                                        verify_hash,
                                        0 ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256", ret );
                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                    MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
                return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            }
            break;
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA384_C)
        case MBEDTLS_MD_SHA384:
            verify_hash_len = 48;
            if( ( ret = mbedtls_sha512( verify_buffer,
                                        verify_buffer_len,
                                        verify_hash,
                                        1 ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha384", ret );
                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                    MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
                return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            }
            break;
#endif /* MBEDTLS_SHA384_C */

#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA512:
            verify_hash_len = 64;
            if( ( ret = mbedtls_sha512( verify_buffer,
                                        verify_buffer_len,
                                        verify_hash,
                                        0 ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512", ret );
                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                    MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
                return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            }
            break;
#endif /* MBEDTLS_SHA512_C */

    default:
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Certificate Verify: Unknown signature algorithm." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                    MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );

    if( ( ret = mbedtls_pk_verify_ext( sig_alg, NULL,
                                       &ssl->session_negotiate->peer_cert->pk,
                                       md_alg, verify_hash, verify_hash_len,
                                       buf, signature_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_verify_ext", ret );

        /* RFC 8446 section 4.4.3
         *
         * If the verification fails, the receiver MUST terminate the handshake
         * with a "decrypt_error" alert.
         */
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR, ret );

        return( ret );
    }

    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

int mbedtls_ssl_tls13_process_certificate_verify( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Coordination step */
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate verify" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_process_certificate_verify_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) // TBD: double-check
    if( ret == SSL_CERTIFICATE_VERIFY_READ )
    {
        unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
        size_t verify_buffer_len;
        unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
        size_t transcript_len;
        unsigned char *buf;
        size_t buf_len;

        /* Need to calculate the hash of the transcript first
         * before reading the message since otherwise it gets
         * included in the transcript
         */
        ret = mbedtls_ssl_get_handshake_transcript( ssl,
                               ssl->handshake->ciphersuite_info->mac,
                               transcript, sizeof( transcript ),
                               &transcript_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash", transcript, transcript_len );

        /* Create verify structure */
        ssl_tls13_create_verify_structure( transcript,
                                           transcript_len,
                                           verify_buffer,
                                           &verify_buffer_len,
                                           !ssl->conf->endpoint );

        MBEDTLS_SSL_PROC_CHK(
            mbedtls_ssl_tls1_3_fetch_handshake_msg( ssl,
                    MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len ) );

        /* Process the message contents */
        MBEDTLS_SSL_PROC_CHK(
            ssl_tls13_process_certificate_verify_parse( ssl,
                buf, buf + buf_len, verify_buffer, verify_buffer_len ) );

        mbedtls_ssl_tls1_3_add_hs_msg_to_checksum( ssl,
                            MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, buf, buf_len );
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
    if( ret == SSL_CERTIFICATE_VERIFY_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate verify" ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }


cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate verify" ) );
    return( ret );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS_C */
