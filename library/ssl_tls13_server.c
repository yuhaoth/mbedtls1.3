/*
 *  TLS 1.3 server-side functions
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

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include "mbedtls/debug.h"

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"
#include "ecdh_misc.h"

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

/* From RFC 8446:
 *   struct {
 *       select (Handshake.msg_type) {
 *           case client_hello:
 *                ProtocolVersion versions<2..254>;
 *           case server_hello: // and HelloRetryRequest
 *                ProtocolVersion selected_version;
 *       };
 *   } SupportedVersions;
 */
static int ssl_tls13_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    size_t versions_len;
    int tls13_supported = 0;
    int major_ver, minor_ver;
    const unsigned char *p = buf;
    const unsigned char *versions_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );

    versions_len = p[0];
    p += 1;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, versions_len );
    if( versions_len % 2 != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid supported version list length %" MBEDTLS_PRINTF_SIZET,
                                    versions_len ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    versions_end = p + versions_len;
    while( p < versions_end )
    {
        mbedtls_ssl_read_version( &major_ver, &minor_ver, ssl->conf->transport, p );

        /* In this implementation we only support TLS 1.3 and DTLS 1.3. */
        if( major_ver == MBEDTLS_SSL_MAJOR_VERSION_3 &&
            minor_ver == MBEDTLS_SSL_MINOR_VERSION_4 )
        {
            tls13_supported = 1;
            break;
        }

        p += 2;
    }

    if( tls13_supported == 0 )
    {
        /* Here we only support TLS 1.3, we need report "bad protocol" if it
         * doesn't support TLS 1.2.
         */

        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLS 1.3 is not supported by the client" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Negotiated version. Supported is [%d:%d]",
                              major_ver, minor_ver ) );

    ssl->major_ver = major_ver;
    ssl->minor_ver = minor_ver;
    return( 0 );
}

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )
/* This function parses the TLS 1.3 supported_groups extension and
 * stores the received groups in ssl->handshake->curves.
 *
 * From RFC 8446:
 *   enum {
 *       ... (0xFFFF)
 *   } NamedGroup;
 *   struct {
 *       NamedGroup named_group_list<2..2^16-1>;
 *   } NamedGroupList;
 */
static int ssl_tls13_parse_supported_groups_ext(
                mbedtls_ssl_context *ssl,
                const unsigned char *buf, const unsigned char *end )
{

    size_t named_group_list_len, curve_list_len;
    const unsigned char *p = buf;
    const mbedtls_ecp_curve_info *curve_info, **curves;
    const unsigned char *extentions_end;

    MBEDTLS_SSL_DEBUG_BUF( 3, "supported_groups extension", p, end - buf );
    named_group_list_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, named_group_list_len );
    if( named_group_list_len % 2 != 0 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    /*       At the moment, this can happen when receiving a second
     *       ClientHello after an HRR. We should properly reset the
     *       state upon receiving an HRR, in which case we should
     *       not observe handshake->curves already being allocated. */
    if( ssl->handshake->curves != NULL )
    {
        mbedtls_free( (void *) ssl->handshake->curves );
        ssl->handshake->curves = NULL;
    }

    /* Don't allow our peer to make us allocate too much memory,
     * and leave room for a final 0
     */
    curve_list_len = named_group_list_len / 2 + 1;
    if( curve_list_len > MBEDTLS_ECP_DP_MAX )
        curve_list_len = MBEDTLS_ECP_DP_MAX;

    if( ( curves = mbedtls_calloc( curve_list_len, sizeof( *curves ) ) ) == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    extentions_end = p + named_group_list_len;
    ssl->handshake->curves = curves;

    while ( p < extentions_end && curve_list_len > 1 )
    {
        uint16_t tls_grp_id = MBEDTLS_GET_UINT16_BE( p, 0 );
        curve_info = mbedtls_ecp_curve_info_from_tls_id( tls_grp_id );

        /* mbedtls_ecp_curve_info_from_tls_id() uses the mbedtls_ecp_curve_info
         * data structure (defined in ecp.c), which only includes the list of
         * curves implemented. Hence, we only add curves that are also supported
         * and implemented by the server.
         */
        if( curve_info != NULL )
        {
            *curves++ = curve_info;
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "supported curve: %s", curve_info->name ) );
            curve_list_len--;
        }

        p += 2;
    }

    return( 0 );

}
#endif /* MBEDTLS_ECDH_C || ( MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECDH_C)
/*
 *  ssl_tls13_parse_key_shares_ext() verifies whether the information in the
 *  extension is correct and stores the provided key shares. Whether this is an
 *  acceptable key share depends on the selected ciphersuite.
 *
 *  Possible return values are:
 *  - 0: Successful processing of the client provided key share extension.
 *  - MBEDTLS_ERR_SSL_HRR_REQUIRED: The key share provided by the client
 *    does not match a group supported by the server. A HelloRetryRequest will
 *    be needed.
 *  - Another negative return value for fatal errors.
*/

static int ssl_tls13_parse_key_shares_ext( mbedtls_ssl_context *ssl,
                                           const unsigned char *buf,
                                           const unsigned char *end )
{
    int ret = 0;
    unsigned char const *p = buf;
    unsigned char const *extentions_end;

    size_t total_extensions_len, key_share_len;
    int match_found = 0;

    /* From RFC 8446:
     *
     * struct {
     *     KeyShareEntry client_shares<0..2^16-1>;
     * } KeyShareClientHello;
     *
     */

    /* Read total legnth of KeyShareClientHello */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );

    total_extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, total_extensions_len );

    ssl->handshake->offered_group_id = 0;
    extentions_end = p + total_extensions_len;

    /* We try to find a suitable key share entry and copy it to the
     * handshake context. Later, we have to find out whether we can do
     * something with the provided key share or whether we have to
     * dismiss it and send a HelloRetryRequest message.
     */

    for( ; p < extentions_end; p += key_share_len + 4 )
    {
        uint16_t group;

        /*
         * struct {
         *    NamedGroup group;
         *    opaque key_exchange<1..2^16-1>;
         * } KeyShareEntry;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extentions_end, 4 );

        group = MBEDTLS_GET_UINT16_BE( p, 0 );
        key_share_len = MBEDTLS_GET_UINT16_BE( p, 2 );


        /* Continue parsing even if we have already found a match,
         * for input validation purposes.
         */
        if( match_found == 1 )
        {
            // p += 2 ;
            continue;
        }

        /*
         * NamedGroup matching
         *
         * For now, we only support ECDHE groups, but e.g.

         * Type 1: ECDHE shares
         *
         * - Check if we recognize the group
         * - Check if it's supported
         */
        match_found = 1;

        if( mbedtls_ssl_tls13_named_group_is_ecdhe( group ) )
        {
            const mbedtls_ecp_curve_info *curve_info =
                mbedtls_ecp_curve_info_from_tls_id( group );
            if( curve_info == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid TLS curve group id" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }



            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );

            ret = mbedtls_ssl_tls13_read_public_ecdhe_share( ssl, p + 2,
                                                             end - p - 2 );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_read_public_ecdhe_share", ret );
                return( ret );
            }
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Unrecognized NamedGroup %u",
                                        (unsigned) group ) );
            return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        ssl->handshake->offered_group_id = group;
    }

    if( match_found == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching key share" ) );
        return( MBEDTLS_ERR_SSL_HRR_REQUIRED );
    }
    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

static void ssl_tls13_debug_print_client_hello_exts( mbedtls_ssl_context *ssl )
{
    ((void) ssl);

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Supported Extensions:" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- KEY_SHARE_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_KEY_SHARE ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- PSK_KEY_EXCHANGE_MODES_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- PRE_SHARED_KEY_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SIGNATURE_ALGORITHM_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SIG_ALG ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SUPPORTED_GROUPS_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_GROUPS ) >0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SUPPORTED_VERSION_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_VERSIONS ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#if defined ( MBEDTLS_SSL_SERVER_NAME_INDICATION )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SERVERNAME_EXTENSION    ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SERVERNAME ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
}

static int ssl_tls13_client_hello_has_exts( mbedtls_ssl_context *ssl,
                                      int ext_id_mask )
{
    int masked = ssl->handshake->extensions_present & ext_id_mask;
    return( masked == ext_id_mask );
}

static int ssl_tls13_client_hello_has_cert_extensions( mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts( ssl,
                          MBEDTLS_SSL_EXT_SUPPORTED_GROUPS |
                          MBEDTLS_SSL_EXT_KEY_SHARE        |
                          MBEDTLS_SSL_EXT_SIG_ALG ) );
}

static int ssl_tls13_check_certificate_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) )
        return( 0 );

    if( !ssl_tls13_client_hello_has_cert_extensions( ssl ) )
        return( 0 );

    ssl->handshake->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
    return( 1 );
}

/*
 *
 * STATE HANDLING: ClientHello
 *
 * There are three possible classes of outcomes when parsing the CH:
 *
 * 1) The CH was well-formed and matched the server's configuration.
 *
 *    In this case, the server progresses to sending its ServerHello.
 *
 * 2) The CH was well-formed but didn't match the server's configuration.
 *
 *    For example, the client might not have offered a key share which
 *    the server supports, or the server might require a cookie.
 *
 *    In this case, the server sends a HelloRetryRequest.
 *
 * 3) The CH was ill-formed
 *
 *    In this case, we abort the handshake.
 *
 */

/*
 * Structure of this message:
 *
 *       uint16 ProtocolVersion;
 *       opaque Random[32];
 *
 *       uint8 CipherSuite[2];    // Cryptographic suite selector
 *
 *       struct {
 *           ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *           Random random;
 *           opaque legacy_session_id<0..32>;
 *           CipherSuite cipher_suites<2..2^16-2>;
 *           opaque legacy_compression_methods<1..2^8-1>;
 *           Extension extensions<8..2^16-1>;
 *       } ClientHello;
 */

#define SSL_CLIENT_HELLO_OK           0
#define SSL_CLIENT_HELLO_HRR_REQUIRED 1

static int ssl_tls13_parse_client_hello( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    int ret;
    size_t i, j;
    size_t legacy_session_id_len;
    size_t cipher_suites_len;
    size_t extensions_len;
    const unsigned char *cipher_suites_start;
    const unsigned char *p = buf;
    const unsigned char *extensions_end;

    const int* cipher_suites;
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info;

    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

    /*
     * ClientHello layer:
     *     0  .   1   protocol version
     *     2  .  33   random bytes ( starting with 4 bytes of Unix time )
     *    34  .  34   session id length ( 1 byte )
     *    35  . 34+x  session id
     *   35+x . 35+x  DTLS only: cookie length ( 1 byte )
     *   36+x .  ..   DTLS only: cookie
     *    ..  .  ..   ciphersuite list length ( 2 bytes )
     *    ..  .  ..   ciphersuite list
     *    ..  .  ..   compression alg. list length ( 1 byte )
     *    ..  .  ..   compression alg. list
     *    ..  .  ..   extensions length ( 2 bytes, optional )
     *    ..  .  ..   extensions ( optional )
     */

    /* Needs to be updated due to mandatory extensions
     * Minimal length ( with everything empty and extensions ommitted ) is
     * 2 + 32 + 1 + 2 + 1 = 38 bytes. Check that first, so that we can
     * read at least up to session id length without worrying.
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 38 );

    /* ...
     * ProtocolVersion legacy_version = 0x0303; // TLS 1.2
     * ...
     * with ProtocolVersion defined as:
     * uint16 ProtocolVersion;
     */
    if( !( p[0] == MBEDTLS_SSL_MAJOR_VERSION_3 &&
           p[1] == MBEDTLS_SSL_MINOR_VERSION_3 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        ret = MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION;
        return ret;
    }
    p += 2;

    /*
     * Save client random
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );

    memcpy( &ssl->handshake->randbytes[0], p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /*
     * Parse session ID
     */
    legacy_session_id_len = p[0];
    p++;

    if( legacy_session_id_len > 32 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ssl->session_negotiate->id_len = legacy_session_id_len;

    /* Note that this field is echoed even if
     * the client's value corresponded to a cached pre-TLS 1.3 session
     * which the server has chosen not to resume. A client which
     * receives a legacy_session_id_echo field that does not match what
     * it sent in the ClientHello MUST abort the handshake with an
     * "illegal_parameter" alert.
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, session id",
                           buf, legacy_session_id_len );

    memcpy( &ssl->session_negotiate->id[0], p, legacy_session_id_len );
    p += legacy_session_id_len;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    cipher_suites_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, cipher_suites_len );

    /* store pointer to ciphersuite list */
    cipher_suites_start = p;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, ciphersuitelist",
                          p, cipher_suites_len );

    /* skip cipher_suites for now */
    p += cipher_suites_len;

    /* ...
     * uint8 legacy_compression_method = 0;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    if( p[0] != 1 || p[1] != MBEDTLS_SSL_COMPRESS_NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad legacy compression method (%d)", p[0] ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return ( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }
    p += 2;

    /*
     * Check the extensions length
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    extensions_end = p + extensions_len;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", p, extensions_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;
        const unsigned char *extension_data_end;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );
        extension_data_end = p + extension_data_len;

        switch( extension_type )
        {
#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported group extension" ) );

                /* Supported Groups Extension
                 *
                 * When sent by the client, the "supported_groups" extension
                 * indicates the named groups which the client supports,
                 * ordered from most preferred to least preferred.
                 */
                ret = ssl_tls13_parse_supported_groups_ext( ssl, p,
                            extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                "mbedtls_ssl_parse_supported_groups_ext", ret );
                    return( ret );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_GROUPS;
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECDH_C)
            case MBEDTLS_TLS_EXT_KEY_SHARE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key share extension" ) );

                /*
                 * Key Share Extension
                 *
                 * When sent by the client, the "key_share" extension
                 * contains the endpoint's cryptographic parameters for
                 * ECDHE/DHE key establishment methods.
                 */
                ret = ssl_tls13_parse_key_shares_ext( ssl, p, extension_data_end );
                if( ret == MBEDTLS_ERR_SSL_HRR_REQUIRED )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 2, ( "HRR needed " ) );
                    ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
                }

                if( ret != 0 )
                    return( ret );

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
                break;
#endif /* MBEDTLS_ECDH_C */

            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported versions extension" ) );

                ret = ssl_tls13_parse_supported_versions_ext(
                      ssl, p, extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                ( "ssl_tls13_parse_supported_versions_ext" ), ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_VERSIONS;
                break;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found signature_algorithms extension" ) );

                ret = mbedtls_ssl_tls13_parse_sig_alg_ext( ssl, p,
                                                           extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1,
                    ( "ssl_parse_supported_signature_algorithms_server_ext ( %d )",
                      ret ) );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIG_ALG;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                        ( "unknown extension found: %ud ( ignoring )",
                          extension_type ) );
        }

        p += extension_data_len;
    }

    /* Update checksum with either
     * - The entire content of the CH message, if no PSK extension is present
     * - The content up to but excluding the PSK extension, if present.
     */
    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, p - buf );
    /*
     * Search for a matching ciphersuite
     */
    cipher_suites = ssl->conf->ciphersuite_list;
    ciphersuite_info = NULL;
    for ( j = 0, p = cipher_suites_start; j < cipher_suites_len; j += 2, p += 2 )
    {
        for ( i = 0; cipher_suites[i] != 0; i++ )
        {
            if( MBEDTLS_GET_UINT16_BE(p, 0) != cipher_suites[i] )
                continue;

            ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(
                               cipher_suites[i] );

            if( ciphersuite_info == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG(
                1,
                ( "mbedtls_ssl_ciphersuite_from_id: should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            goto have_ciphersuite;

        }
    }



    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );

have_ciphersuite:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "selected ciphersuite: %s",
                                ciphersuite_info->name ) );

    ssl->session_negotiate->ciphersuite = cipher_suites[i];
    ssl->handshake->ciphersuite_info = ciphersuite_info;

    /* List all the extensions we have received */
    ssl_tls13_debug_print_client_hello_exts( ssl );

    /*
     * Determine the key exchange algorithm to use.
     * There are three types of key exchanges supported in TLS 1.3:
     * - (EC)DH with ECDSA,
     * - (EC)DH with PSK,
     * - plain PSK.
     *
     * The PSK-based key exchanges may additionally be used with 0-RTT.
     *
     * Our built-in order of preference is
     *  1 ) Plain PSK Mode
     *  2 ) (EC)DHE-PSK Mode
     *  3 ) Certificate Mode
     */

    if( !ssl_tls13_check_certificate_key_exchange( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG(
                1,
                ( "ClientHello message misses mandatory extensions." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION ,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    return( 0 );
}

/* Update the handshake state machine */

static int ssl_tls13_postprocess_client_hello( mbedtls_ssl_context* ssl )
{
    int ret = 0;

    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
             "mbedtls_ssl_tls1_3_key_schedule_stage_early", ret );
        return( ret );
    }

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    return( 0 );

}

/*
 * Main entry point from the state machine; orchestrates the otherfunctions.
 */

static int ssl_tls13_process_client_hello( mbedtls_ssl_context *ssl )
{

    int ret = 0;
    unsigned char* buf = NULL;
    size_t buflen = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse client hello" ) );

    ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                          ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                          &buf, &buflen ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_parse_client_hello( ssl, buf,
                                                            buf + buflen ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_client_hello( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );
    return( ret );
}

/*
 * StateHanler: MBEDTLS_SSL_SERVER_HELLO
 */
static int ssl_tls13_prepare_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *server_randbyes =
                    ssl->handshake->randbytes + MBEDTLS_CLIENT_HELLO_RANDOM_LEN;
    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng, server_randbyes,
                                  MBEDTLS_SERVER_HELLO_RANDOM_LEN ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_rng", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes", server_randbyes,
                           MBEDTLS_SERVER_HELLO_RANDOM_LEN );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    return( ret );
}

/*
 * ssl_tls13_write_selected_version_ext():
 *
 * struct {
 *      ProtocolVersion selected_version;
 * } SupportedVersions;
 */
static int ssl_tls13_write_selected_version_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, write selected_version" ) );

    /* Check if we have space to write the extension:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - selected_version       (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS, p, 0 );

    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( 2, p, 2 );

    /* Write values of supported versions.
     *
     * They are defined by the configuration.
     *
     * Currently, only one version is advertised.
     */
    mbedtls_ssl_write_version( ssl->conf->max_major_ver,
                               ssl->conf->max_minor_ver,
                               ssl->conf->transport, p + 4 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "selected_version: [%d:%d]",
                                ssl->conf->max_major_ver,
                                ssl->conf->max_minor_ver ) );

    *out_len = 6;

    return( 0 );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/* Generate and export a single key share. For hybrid KEMs, this can
 * be called multiple times with the different components of the hybrid. */
static int ssl_tls13_key_share_encapsulate( mbedtls_ssl_context *ssl,
                                            uint16_t named_group,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) ssl);
    ((void) named_group);
    ((void) buf);
    ((void) end);
    ((void) out_len);
#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( named_group ) )
    {
        ret = mbedtls_ssl_tls13_generate_and_write_ecdh_key_exchange(
                                        ssl, named_group, buf, end, out_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET(
                1, "mbedtls_ssl_tls13_generate_and_write_ecdh_key_exchange",
                ret );
            return( ret );
        }
    }
    else
#endif /* MBEDTLS_ECDH_C */
    if( 0 /* Other kinds of KEMs */ )
    {
    }
    else
    {
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    return( ret );
}

/*
 * ssl_tls13_write_key_share_ext
 *
 * Structure of key_share extension in ServerHello:
 *
 *  struct {
 *          NamedGroup group;
 *          opaque key_exchange<1..2^16-1>;
 *      } KeyShareEntry;
 *  struct {
 *          KeyShareEntry server_share;
 *      } KeyShareServerHello;
 */
static int ssl_tls13_write_key_share_ext( mbedtls_ssl_context *ssl,
                                          unsigned char *buf,
                                          unsigned char *end,
                                          size_t *out_len )
{
    unsigned char *p = buf;
    unsigned char *start = buf;
    uint16_t group = ssl->handshake->offered_group_id ;
    unsigned char *server_share = buf + 4;
    unsigned char *key_exchange = buf + 6;
    size_t key_exchange_length;
    int ret;

    *out_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding key share extension" ) );

    /* Check if we have space for header and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - group                  (2 bytes)
     * - key_exchange_length    (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 8 );

    p += 8;
    /* When we introduce PQC-ECDHE hybrids, we'll want to call this
     * function multiple times. */
    ret = ssl_tls13_key_share_encapsulate( ssl, group, key_exchange + 2,
                                           end, &key_exchange_length );
    if( ret != 0 )
        return( ret );
    p += key_exchange_length;
    /* Write length of key_exchange */
    MBEDTLS_PUT_UINT16_BE( key_exchange_length, key_exchange, 0 );

    *out_len = p - start;

    /* Write group ID */
    MBEDTLS_PUT_UINT16_BE( group, server_share, 0 );

    /* Write extension header */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, start, 0 );

    /* Write total extension length */
    MBEDTLS_PUT_UINT16_BE( p - server_share, start, 2 );

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 * Structure of ServerHello message:
 *
 *     struct {
 *        ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *        Random random;
 *        opaque legacy_session_id_echo<0..32>;
 *        CipherSuite cipher_suite;
 *        uint8 legacy_compression_method = 0;
 *        Extension extensions<6..2^16-1>;
 *    } ServerHello;
 */
static int ssl_tls13_write_server_hello_body( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len )
{
    int ret = 0;
    size_t output_len;               /* Length of buffer used by function */
    unsigned char *server_randbyes =
                    ssl->handshake->randbytes + MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

    /* Buffer management */
    unsigned char *p = buf;
    unsigned char *start = buf;
    unsigned char *extension_start;

    *out_len = 0;

    /*
     * Write legacy_version
     *    ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
     *
     *  For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( 0x0303, p, 0 );
    p += 2;

    /* Write the random bytes ( random ).*/
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    memcpy( p, server_randbyes, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    /*
     * Write legacy_session_id_echo
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 + ssl->session_negotiate->id_len );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    if( ssl->session_negotiate->id_len > 0 )
    {
        memcpy( p, &ssl->session_negotiate->id[0],
                ssl->session_negotiate->id_len );
        p += ssl->session_negotiate->id_len;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "session id length ( %"
                                        MBEDTLS_PRINTF_SIZET " )",
                                    ssl->session_negotiate->id_len ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
    }

    /*
     * Write ciphersuite
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( ssl->session_negotiate->ciphersuite, p, 0 );
    p += 2;
    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "server hello, chosen ciphersuite: %s ( id=%d )",
          mbedtls_ssl_get_ciphersuite_name(
            ssl->session_negotiate->ciphersuite ),
          ssl->session_negotiate->ciphersuite ) );

    /* write legacy_compression_method = ( 0 ) */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    *p++ = 0x0;

    /* Extensions */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    extension_start = p;
    p += 2;

    /* Add supported_version extension */
    if( ( ret = ssl_tls13_write_selected_version_ext(
                                            ssl, p, end, &output_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_selected_version_ext",
                               ret );
        return( ret );
    }
    p += output_len;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
    {
        ret = ssl_tls13_write_key_share_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

    /* Write length information */
    MBEDTLS_PUT_UINT16_BE( p - extension_start - 2, extension_start, 0 );

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello extensions", extension_start, p - extension_start );

    *out_len = p - start;

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello", start, *out_len );

    return( ret );
}


static int ssl_tls13_finalize_server_hello( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
    return( 0 );
}

static int ssl_tls13_write_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write server hello" ) );

    /* Preprocessing */

    /* This might lead to ssl_tls13_process_server_hello() being called
     * multiple times. The implementation of
     * ssl_tls13_process_server_hello_preprocess() must either be safe to be
     * called multiple times, or we need to add state to omit this call once
     * we're calling ssl_tls13_process_server_hello() multiple times.
     */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_server_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                                MBEDTLS_SSL_HS_SERVER_HELLO, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_server_hello_body( ssl, buf,
                                                             buf + buf_len,
                                                             &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_SERVER_HELLO, buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_server_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );
cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server hello" ) );
    return( ret );
}

/*
 * State Handler: MBEDTLS_SSL_HELLO_RETRY_REQUEST
 */

static int ssl_tls13_write_hello_retry_request_coordinate(
                                                    mbedtls_ssl_context *ssl )
{
    if( ssl->handshake->hello_retry_request_count > 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Too many HRRs" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    return( 0 );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
static int ssl_tls13_write_hrr_key_share_ext( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len )
{

    /* key_share Extension
     *
     *  struct {
     *    select (Handshake.msg_type) {
     *      ...
     *      case hello_retry_request:
     *          NamedGroup selected_group;
     *      ...
     *    };
     * } KeyShare;
     */

    *out_len = 0;

    /* For a pure PSK-based ciphersuite there is no key share to declare. */
    if( ! mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    /* We should only send the key_share extension if the client's initial
     * key share was not acceptable. */
    if( ssl->handshake->offered_group_id != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Skip key_share extension in HRR" ) );
        return( 0 );
    }

    /* Find common curve */

    for( const mbedtls_ecp_curve_info **curve = ssl->handshake->curves;
            *curve != NULL; curve++ )
    {
        if( mbedtls_ssl_check_curve_tls_id( ssl, (*curve)->tls_id ) == 0 )
        {
            uint16_t selected_group = (*curve)->tls_id ;

            /* extension header, extension length, NamedGroup value */
            MBEDTLS_SSL_CHK_BUF_READ_PTR( buf, end, 6 );

            /* Write extension header */
            MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0 );

            /* Write extension length */
            MBEDTLS_PUT_UINT16_BE( 2, buf, 2 );

            /* Write selected group */
            MBEDTLS_PUT_UINT16_BE( selected_group, buf, 4 );

            MBEDTLS_SSL_DEBUG_MSG( 3,
                ( "NamedGroup in HRR: %s",
                  mbedtls_ssl_named_group_to_str( selected_group ) ) );

            *out_len = 6;
            return( 0 );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching named group found" ) );
    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

static int ssl_tls13_write_hello_retry_request_body( mbedtls_ssl_context *ssl,
                                                     unsigned char *buf,
                                                     unsigned char *end,
                                                     size_t *out_len )
{
    int ret;
    unsigned char *p = buf;
    unsigned char *start = buf;
    size_t output_len;
    unsigned char *extension_start;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write hello retry request" ) );

    *out_len = 0;

    /*
     * struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random ( with magic value );
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<0..2^16-1>;
     * } ServerHello; --- aka HelloRetryRequest
     */


    /*
     * Write legacy_version
     *    ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
     *
     *  For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( 0x0303, p, 0 );
    p += 2;

    /* write magic string (as a replacement for the random value) */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    memcpy( p, mbedtls_ssl_tls13_hello_retry_requst_magic,
            MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /*
     * Write legacy_session_id_echo
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 + ssl->session_negotiate->id_len );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    if( ssl->session_negotiate->id_len > 0 )
    {
        memcpy( p, &ssl->session_negotiate->id[0],
                ssl->session_negotiate->id_len );
        p += ssl->session_negotiate->id_len;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "session id length ( %"
                                        MBEDTLS_PRINTF_SIZET " )",
                                    ssl->session_negotiate->id_len ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
    }

    /*
     * Write ciphersuite
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( ssl->session_negotiate->ciphersuite, p, 0 );
    p += 2;
    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "server hello, chosen ciphersuite: %s ( id=%d )",
          mbedtls_ssl_get_ciphersuite_name(
            ssl->session_negotiate->ciphersuite ),
          ssl->session_negotiate->ciphersuite ) );

    /* write legacy_compression_method = ( 0 ) */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    *p++ = 0x0;

    /* Extensions */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    extension_start = p;
    p += 2;

    /* Add supported_version extension */
    if( ( ret = ssl_tls13_write_supported_versions_ext(
                                            ssl, p, end, &output_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_supported_versions_ext",
                               ret );
        return( ret );
    }
    p += output_len;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    /* Add key_share extension, if necessary */
    if( mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
    {
        ret = ssl_tls13_write_hrr_key_share_ext( ssl, p, end, &output_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_hrr_key_share_ext", ret );
            return( ret );
        }
        p += output_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

    /* Write length information */
    MBEDTLS_PUT_UINT16_BE( p - extension_start - 2, extension_start, 0 );

    MBEDTLS_SSL_DEBUG_BUF( 4, "hello retry request extensions",
                           extension_start, p - extension_start );

    *out_len = p - start;

    MBEDTLS_SSL_DEBUG_BUF( 3, "hello retry request", start, *out_len );

    *out_len = p - buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write hello retry request" ) );
    return( 0 );
}

static int ssl_tls13_finalize_hello_retry_request( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ssl->handshake->hello_retry_request_count++;

    /* Reset everything that's going to be re-generated in the new ClientHello.
     *
     * Currently, we're always resetting the key share, even if the server
     * was fine with it. Once we have separated key share generation from
     * key share writing, we can confine this to the case where the server
     * requested a different share. */
    ret = mbedtls_ssl_tls13_reset_key_share( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );

    return( 0 );
}

static int ssl_tls13_write_hello_retry_request( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_hello_retry_request_coordinate( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                       MBEDTLS_SSL_HS_SERVER_HELLO, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_hello_retry_request_body(
                              ssl, buf, buf + buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_SERVER_HELLO, buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_hello_retry_request( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg( ssl, buf_len,
                                                            msg_len ) );
cleanup:

    return( ret );
}

/*
 * TLS 1.3 State Machine -- server side
 */
int mbedtls_ssl_tls13_handshake_server_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls13 server state: %s(%d)",
                                mbedtls_ssl_states_str( ssl->state ),
                                ssl->state ) );

    switch( ssl->state )
    {
        /* start state */
        case MBEDTLS_SSL_HELLO_REQUEST:
            ssl->handshake->hello_retry_request_count = 0;
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
            break;

        /* ----- READ CLIENT HELLO ----*/
        case MBEDTLS_SSL_CLIENT_HELLO:
            ret = ssl_tls13_process_client_hello( ssl );
            if( ret != 0 )
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_process_client_hello", ret );
            break;

        /* ----- WRITE SERVER HELLO ----*/
        case MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_tls13_write_server_hello( ssl );
            break;

        /* ----- WRITE HELLO RETRY REQUEST ----*/
        case MBEDTLS_SSL_HELLO_RETRY_REQUEST:
            ret = ssl_tls13_write_hello_retry_request( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_hello_retry_request", ret );
                return( ret );
            }
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_TLS1_3 */
