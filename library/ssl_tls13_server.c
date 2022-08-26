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

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/constant_time.h"

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"
#include <string.h>
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_USE_MPS)
#include "mps_all.h"
#endif /* MBEDTLS_SSL_USE_MPS */

#include <string.h>

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#include "ecp_internal.h"
#endif /* MBEDTLS_ECP_C */

#include "mbedtls/hkdf.h"

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
#include "mbedtls/ssl_ticket.h"
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif /* MBEDTLS_HAVE_TIME */

/* From RFC 8446:
 *   struct {
 *          ProtocolVersion versions<2..254>;
 *   } SupportedVersions;
 */
static int ssl_tls13_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    const unsigned char *p = buf;
    size_t versions_len;
    const unsigned char *versions_end;
    uint16_t tls_version;
    int tls13_supported = 0;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    versions_len = p[0];
    p += 1;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, versions_len );
    versions_end = p + versions_len;
    while( p < versions_end )
    {
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, versions_end, 2 );
        tls_version = mbedtls_ssl_read_version( p, ssl->conf->transport );
        p += 2;

        /* In this implementation we only support TLS 1.3 and DTLS 1.3. */
        if( tls_version == MBEDTLS_SSL_VERSION_TLS1_3 )
        {
            tls13_supported = 1;
            break;
        }
    }

    if( !tls13_supported )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLS 1.3 is not supported by the client" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Negotiated version. Supported is [%04x]",
                              (unsigned int)tls_version ) );

    return( 0 );
}

#if defined(MBEDTLS_ECDH_C)
/*
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
    const unsigned char *p = buf;
    size_t named_group_list_len;
    const unsigned char *named_group_list_end;

    MBEDTLS_SSL_DEBUG_BUF( 3, "supported_groups extension", p, end - buf );
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    named_group_list_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, named_group_list_len );
    named_group_list_end = p + named_group_list_len;
    ssl->handshake->hrr_selected_group = 0;

    while( p < named_group_list_end )
    {
        uint16_t named_group;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, named_group_list_end, 2 );
        named_group = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "got named group: %d", named_group ) );

        if( ! mbedtls_ssl_named_group_is_offered( ssl, named_group ) ||
            ! mbedtls_ssl_named_group_is_supported( named_group ) ||
            ssl->handshake->hrr_selected_group != 0 )
        {
            continue;
        }

        MBEDTLS_SSL_DEBUG_MSG(
                2, ( "add named group (%04x) into received list.",
                     named_group ) );
        ssl->handshake->hrr_selected_group = named_group;
    }

    return( 0 );

}
#endif /* MBEDTLS_ECDH_C */

#define SSL_TLS1_3_PARSE_KEY_SHARES_EXT_NO_MATCH 1

#if defined(MBEDTLS_ECDH_C)
/*
 *  ssl_tls13_parse_key_shares_ext() verifies whether the information in the
 *  extension is correct and stores the first acceptable key share and its associated group.
 *
 *  Possible return values are:
 *  - 0: Successful processing of the client provided key share extension.
 *  - SSL_TLS1_3_PARSE_KEY_SHARES_EXT_NO_MATCH: The key shares provided by the client
 *    does not match a group supported by the server. A HelloRetryRequest will
 *    be needed.
 *  - A negative value for fatal errors.
*/

static int ssl_tls13_parse_key_shares_ext( mbedtls_ssl_context *ssl,
                                           const unsigned char *buf,
                                           const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char const *p = buf;
    unsigned char const *client_shares_end;
    size_t client_shares_len, key_exchange_len;
    int match_found = 0;

    /* From RFC 8446:
     *
     * struct {
     *     KeyShareEntry client_shares<0..2^16-1>;
     * } KeyShareClientHello;
     *
     */

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    client_shares_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, client_shares_len );

    ssl->handshake->offered_group_id = 0;
    client_shares_end = p + client_shares_len;

    /* We try to find a suitable key share entry and copy it to the
     * handshake context. Later, we have to find out whether we can do
     * something with the provided key share or whether we have to
     * dismiss it and send a HelloRetryRequest message.
     */

    for( ; p < client_shares_end; p += key_exchange_len )
    {
        uint16_t group;

        /*
         * struct {
         *    NamedGroup group;
         *    opaque key_exchange<1..2^16-1>;
         * } KeyShareEntry;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, client_shares_end, 4 );
        group = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;
        key_exchange_len = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, client_shares_end, key_exchange_len );

        /* Continue parsing even if we have already found a match,
         * for input validation purposes.
         */
        if( match_found == 1 )
            continue;

        if( ! mbedtls_ssl_named_group_is_offered( ssl, group ) ||
            ! mbedtls_ssl_named_group_is_supported( group ) )
        {
            continue;
        }

        /*
         * For now, we only support ECDHE groups.
         */
        if( mbedtls_ssl_tls13_named_group_is_ecdhe( group ) )
        {
            const mbedtls_ecp_curve_info *curve_info =
                    mbedtls_ecp_curve_info_from_tls_id( group );
            ((void) curve_info);
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );
            ret = mbedtls_ssl_tls13_read_public_ecdhe_share(
                    ssl, p - 2, key_exchange_len + 2 );
            if( ret != 0 )
                return( ret );

            match_found = 1;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Unrecognized NamedGroup %u",
                                        (unsigned) group ) );
            continue;
        }

        ssl->handshake->offered_group_id = group;
    }

    if( match_found == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching key share" ) );
        return( SSL_TLS1_3_PARSE_KEY_SHARES_EXT_NO_MATCH );
    }

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_DEBUG_C)
static void ssl_tls13_debug_print_client_hello_exts( mbedtls_ssl_context *ssl )
{
    ((void) ssl);

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Supported Extensions:" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- KEY_SHARE_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_KEY_SHARE ) > 0 ) ? "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- PSK_KEY_EXCHANGE_MODES_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) > 0 ) ?
                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- PRE_SHARED_KEY_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_PRE_SHARED_KEY ) > 0 ) ? "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- SIGNATURE_ALGORITHM_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_SIG_ALG ) > 0 ) ? "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- SUPPORTED_GROUPS_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_SUPPORTED_GROUPS ) >0 ) ?
                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- SUPPORTED_VERSION_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_SUPPORTED_VERSIONS ) > 0 ) ?
                "TRUE" : "FALSE" ) );
#if defined ( MBEDTLS_SSL_SERVER_NAME_INDICATION )
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- SERVERNAME_EXTENSION    ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_SERVERNAME ) > 0 ) ?
                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#if defined ( MBEDTLS_SSL_ALPN )
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- ALPN_EXTENSION   ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_ALPN ) > 0 ) ?
                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_ALPN */
#if defined ( MBEDTLS_SSL_MAX_FRAGMENT_LENGTH )
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- MAX_FRAGMENT_LENGTH_EXTENSION  ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_MAX_FRAGMENT_LENGTH ) > 0 ) ?
                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */
#if defined ( MBEDTLS_SSL_COOKIE_C )
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- COOKIE_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_COOKIE ) >0 ) ?
                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_COOKIE_C */
#if defined(MBEDTLS_ZERO_RTT)
    MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "- EARLY_DATA_EXTENSION ( %s )",
            ( ( ssl->handshake->extensions_present
                & MBEDTLS_SSL_EXT_EARLY_DATA ) > 0 ) ?
                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_ZERO_RTT*/
}
#endif /* MBEDTLS_DEBUG_C */

static int ssl_tls13_client_hello_has_exts( mbedtls_ssl_context *ssl,
                                            int exts_mask )
{
    int masked = ssl->handshake->extensions_present & exts_mask;
    return( masked == exts_mask );
}

static int ssl_tls13_client_hello_has_exts_for_ephemeral_key_exchange(
        mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts( ssl,
                          MBEDTLS_SSL_EXT_SUPPORTED_GROUPS |
                          MBEDTLS_SSL_EXT_KEY_SHARE        |
                          MBEDTLS_SSL_EXT_SIG_ALG ) );
}

static int ssl_tls13_client_hello_has_psk_extensions( mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts( ssl,
                MBEDTLS_SSL_EXT_PRE_SHARED_KEY |
                MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) );
}

static int ssl_tls13_client_hello_has_key_share_extensions( mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts( ssl,
                          MBEDTLS_SSL_EXT_SUPPORTED_GROUPS |
                          MBEDTLS_SSL_EXT_KEY_SHARE ) );
}

static int ssl_tls13_check_ephemeral_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) )
        return( 0 );

    if( !ssl_tls13_client_hello_has_exts_for_ephemeral_key_exchange( ssl ) )
        return( 0 );

    ssl->handshake->key_exchange =
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
    return( 1 );
}

static int ssl_tls13_check_psk_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !ssl_tls13_client_hello_has_psk_extensions( ssl ) )
        return( 0 );

    /* Test whether pure PSK is offered by client and supported by us. */
    if( mbedtls_ssl_conf_tls13_psk_enabled( ssl ) &&
        mbedtls_ssl_tls13_psk_enabled( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using a PSK key exchange" ) );
        ssl->handshake->key_exchange = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
        return( 1 );
    }

    /* Test whether PSK-ephemeral is offered by client and supported by us. */
    if( mbedtls_ssl_conf_tls13_psk_ephemeral_enabled( ssl ) &&
        mbedtls_ssl_tls13_psk_ephemeral_enabled( ssl ) &&
        ssl_tls13_client_hello_has_key_share_extensions( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using a ECDHE-PSK key exchange" ) );
        ssl->handshake->key_exchange = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
        return( 1 );
    }

    /* Can't use PSK */
    return( 0 );
}

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
static int ssl_tls13_write_sni_server_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf,
    size_t buflen,
    size_t *olen )
{
    unsigned char *p = buf;
    *olen = 0;

    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SERVERNAME ) == 0 )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding server_name extension" ) );

    if( buflen < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Write extension header */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SERVERNAME, p, 0 );

    /* Write total extension length */
    MBEDTLS_PUT_UINT16_BE( 0, p, 2 );

    *olen = 4;

    return( 0 );
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_tls13_parse_early_data_ext( mbedtls_ssl_context *ssl,
                                           const unsigned char *buf,
                                           size_t len )
{
    ((void) ssl);
    ((void) buf);
    /* From RFC 8446:
     *  struct {} Empty;
     *  struct {
     *     select (Handshake.msg_type) {
     *         case new_session_ticket:   uint32 max_early_data_size;
     *         case client_hello:         Empty;
     *         case encrypted_extensions: Empty;
     *     };
     * } EarlyDataIndication;
     */
    if( len != 0 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
int mbedtls_ssl_tls13_parse_new_session_ticket_server(
    mbedtls_ssl_context *ssl,
    unsigned char *buf,
    size_t len )
{
    int ret;
    unsigned char *ticket_buffer;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse new session ticket" ) );

    if( ssl->conf->f_ticket_parse == NULL ||
        ssl->conf->f_ticket_write == NULL )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket length: %" MBEDTLS_PRINTF_SIZET , len ) );

    if( len == 0 ) return( 0 );

    /* We create a copy of the encrypted ticket since decrypting
     * it into the same buffer will wipe-out the original content.
     * We do, however, need the original buffer for computing the
     * psk binder value.
     */
    ticket_buffer = mbedtls_calloc( len,1 );

    if( ticket_buffer == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    memcpy( ticket_buffer, buf, len );

    if( ( ret = ssl->conf->f_ticket_parse( ssl->conf->p_ticket, ssl->session_negotiate,
                                         ticket_buffer, len ) ) != 0 )
    {
        mbedtls_free( ticket_buffer );
        if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket is not authentic" ) );
        else if( ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED )
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket is expired" ) );
        else
            MBEDTLS_SSL_DEBUG_RET( 1, "ticket_parse", ret );

        return( ret );
    }

    /* We delete the temporary buffer */
    mbedtls_free( ticket_buffer );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse new session ticket" ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_tls13_parse_client_psk_identity_ext(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    size_t len )
{
    int ret = 0;
    unsigned int item_array_length, item_length, sum, length_so_far;
    unsigned char server_computed_binder[MBEDTLS_MD_MAX_SIZE];
    const unsigned char *psk = NULL;
    unsigned char const * const start = buf;
    size_t psk_len = 0;
    unsigned char const *end_of_psk_identities;

    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
    uint32_t obfuscated_ticket_age;
#if defined(MBEDTLS_HAVE_TIME)
    time_t now;
    int64_t diff;
#endif /* MBEDTLS_HAVE_TIME */
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

    /* Read length of array of identities */
    item_array_length = MBEDTLS_GET_UINT16_BE( buf, 0 );
    length_so_far = item_array_length + 2;
    if( length_so_far > len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad psk_identity extension in client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }
    end_of_psk_identities = buf + length_so_far;
    buf += 2;
    sum = 2;
    while( sum < item_array_length + 2 )
    {
        /* Read to psk identity length */
        item_length = MBEDTLS_GET_UINT16_BE( buf, 0 );
        sum = sum + 2 + item_length;

        if( sum > len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "psk_identity length mismatch" ) );

            if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        /*
         * Extract pre-shared key identity provided by the client
         */
        /* jump to identity value itself */
        buf += 2;

        MBEDTLS_SSL_DEBUG_BUF( 3, "received psk identity", buf, item_length );

        if( ssl->conf->f_psk != NULL )
        {
            if( ssl->conf->f_psk( ssl->conf->p_psk, ssl, buf, item_length ) != 0 )
                ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
        }
        else
        {
            /* Identity is not a big secret since clients send it in the clear,
             * but treat it carefully anyway, just in case */
            if( item_length != ssl->conf->psk_identity_len ||
                mbedtls_ct_memcmp( ssl->conf->psk_identity, buf, item_length ) != 0 )
            {
                ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
            }
            else
            {
                /* skip obfuscated ticket age */
                /* TBD: Process obfuscated ticket age ( zero for externally configured PSKs?! ) */
                buf = buf + item_length + 4; /* 4 for obfuscated ticket age */;

                mbedtls_ssl_set_hs_psk( ssl, ssl->conf->psk, ssl->conf->psk_len );
                goto psk_parsing_successful;

            }
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
            /* Check the ticket cache if previous lookup was unsuccessful */
            if( ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY )
            {
                /* copy ticket since it acts as the psk_identity */
                if( ssl->session_negotiate->ticket != NULL )
                {
                    mbedtls_free( ssl->session_negotiate->ticket );
                }
                ssl->session_negotiate->ticket = mbedtls_calloc( 1, item_length );
                if( ssl->session_negotiate->ticket == NULL )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc failed ( %d bytes )", item_length ) );
                    return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
                }
                memcpy( ssl->session_negotiate->ticket, buf, item_length );
                ssl->session_negotiate->ticket_len = item_length;

                ret = mbedtls_ssl_tls13_parse_new_session_ticket_server( ssl,
                                             ssl->session_negotiate->ticket,
                                             item_length );
                if( ret == 0 )
                {
                    /* found a match in the ticket cache; everything is OK */
                    ssl->handshake->resume = 1;

                    /* We put the resumption key into the handshake->psk.
                     *
                     * Note: The key in the ticket is already the final PSK,
                     *       i.e., the HKDF-Expand-Label( resumption_master_secret,
                     *                                    "resumption",
                     *                                    ticket_nonce,
                     *                                    Hash.length )
                     *       function has already been applied.
                     */
                    mbedtls_ssl_set_hs_psk( ssl, ssl->session_negotiate->key,
                                            ssl->session_negotiate->key_len );
                    MBEDTLS_SSL_DEBUG_BUF( 4, "Ticket-resumed PSK:", ssl->session_negotiate->key,
                                           ssl->session_negotiate->key_len );

                    /* obfuscated ticket age follows the identity field, which is
                     * item_length long, containing the ticket */
                    memcpy( &obfuscated_ticket_age, buf+item_length, 4 );

                    MBEDTLS_SSL_DEBUG_MSG( 4, ( "ticket: obfuscated_ticket_age: %u",
                                                obfuscated_ticket_age ) );
                    /*
                     * A server MUST validate that the ticket age for the selected PSK identity
                     * is within a small tolerance of the time since the ticket was issued.
                     */

#if defined(MBEDTLS_HAVE_TIME)
                    now = time( NULL );

                    /* Check #1:
                     *   Is the time when the ticket was issued later than now?
                     */

                    if( now < ssl->session_negotiate->start )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 3,
                               ( "Ticket expired: now=%ld, ticket.start=%ld",
                                 now, ssl->session_negotiate->start ) );
                        ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                    }

                    /* Check #2:
                     *   Is the ticket expired already?
                     */

                    if( now - ssl->session_negotiate->start > ssl->session_negotiate->ticket_lifetime )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 3,
                               ( "Ticket expired ( now - ticket.start=%ld, "\
                                 "ticket.ticket_lifetime=%d",
                                 now - ssl->session_negotiate->start,
                                 ssl->session_negotiate->ticket_lifetime ) );

                        ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                    }

                    /* Check #3:
                     *   Is the ticket age for the selected PSK identity
                     *   (computed by subtracting ticket_age_add from
                     *   PskIdentity.obfuscated_ticket_age modulo 2^32 )
                     *   within a small tolerance of the time since the
                     *   ticket was issued?
                     */

                    diff = ( now - ssl->session_negotiate->start ) -
                        ( obfuscated_ticket_age - ssl->session_negotiate->ticket_age_add );

                    if( diff > MBEDTLS_SSL_TICKET_AGE_TOLERANCE )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "Ticket age outside tolerance window ( diff=%ld )",
                              diff ) );
                        ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                    }

#if defined(MBEDTLS_ZERO_RTT)
                    if( ssl->conf->early_data_enabled == MBEDTLS_SSL_EARLY_DATA_ENABLED )
                    {
                        if( diff <= MBEDTLS_SSL_EARLY_DATA_MAX_DELAY )
                        {
                            ssl->session_negotiate->process_early_data =
                                MBEDTLS_SSL_EARLY_DATA_ENABLED;
                        }
                        else
                        {
                            MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "0-RTT is disabled ( diff=%ld exceeds "\
                              "MBEDTLS_SSL_EARLY_DATA_MAX_DELAY )", diff ) );
                            ssl->session_negotiate->process_early_data =
                                MBEDTLS_SSL_EARLY_DATA_DISABLED;
                            ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                        }
                    }
#endif /* MBEDTLS_ZERO_RTT */
#endif /* MBEDTLS_HAVE_TIME */

                    /* TBD: check ALPN, ciphersuite and SNI as well */

                    /*
                     * If the check failed, the server SHOULD proceed with
                     * the handshake but reject 0-RTT, and SHOULD NOT take any
                     * other action that assumes that this ClientHello is fresh.
                     */

                    /* Disable 0-RTT */
                    if( ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED )
                    {
#if defined(MBEDTLS_ZERO_RTT)
                        if( ssl->conf->early_data_enabled ==
                            MBEDTLS_SSL_EARLY_DATA_ENABLED )
                        {
                            ssl->session_negotiate->process_early_data =
                                MBEDTLS_SSL_EARLY_DATA_DISABLED;
                        }
#else
                        ( ( void )buf );
#endif /* MBEDTLS_ZERO_RTT */
                    }
                }
            }
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
        }
        /* skip the processed identity field and obfuscated ticket age field */
        buf += item_length;
        buf += 4;
        sum = sum + 4;
    }

    if( ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Session ticket expired." ) );
        return( ret );
    }

    if( ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Unknown PSK identity", buf, item_length );
        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                   MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                   MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY ) ) != 0 )
        {
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY );
    }

    if( length_so_far != sum )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad psk_identity extension in client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

psk_parsing_successful:

    /* Update the handshake transcript with the CH content up to
     * but excluding the PSK binder list. */
    ssl->handshake->update_checksum( ssl, start,
                                     (size_t)( end_of_psk_identities - start ) );

    buf = end_of_psk_identities;

    /* Get current state of handshake transcript. */
    ret = mbedtls_ssl_get_handshake_transcript( ssl,
                                                ssl->handshake->ciphersuite_info->mac,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
        return( ret );

    /* read length of psk binder array */
    item_array_length = MBEDTLS_GET_UINT16_BE( buf, 0 );
    length_so_far += item_array_length;
    buf += 2;

    sum = 0;
    while( sum < item_array_length )
    {
        int psk_type;
        /* Read to psk binder length */
        item_length = buf[0];
        sum = sum + 1 + item_length;
        buf += 1;

        if( sum > item_array_length )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "psk binder length mismatch" ) );

            if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        psk = ssl->handshake->psk;
        psk_len = ssl->handshake->psk_len;

        if( ssl->handshake->resume == 1 )
            psk_type = MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION;
        else
            psk_type = MBEDTLS_SSL_TLS1_3_PSK_EXTERNAL;

        ret = mbedtls_ssl_tls13_create_psk_binder( ssl,
                 mbedtls_psa_translate_md( ssl->handshake->ciphersuite_info->mac ),
                 psk, psk_len, psk_type,
                 transcript, server_computed_binder );

        /* We do not check for multiple binders */
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "PSK binder calculation failed." ) );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder ( computed ): ",
                               server_computed_binder, item_length );
        MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder ( received ): ",
                               buf, item_length );

        if( mbedtls_ct_memcmp( server_computed_binder, buf, item_length ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1,
                ( "Received psk binder does not match computed psk binder." ) );

            if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }

        buf += item_length;

        ret = 0;
        goto done;
    }

    /* No valid PSK binder value found */
    /* TODO: Shouldn't we just fall back to a full handshake in this case? */
    ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;

done:

    /* Update the handshake transcript with the binder list. */
    ssl->handshake->update_checksum( ssl,
                                     end_of_psk_identities,
                                     (size_t)( buf - end_of_psk_identities ) );

    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED*/

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/*
 * struct {
 *   select ( Handshake.msg_type ) {
 *      case client_hello:
 *          PskIdentity identities<6..2^16-1>;
 *
 *      case server_hello:
 *          uint16 selected_identity;
 *   }
 * } PreSharedKeyExtension;
 */

static int ssl_tls13_write_server_pre_shared_key_ext( mbedtls_ssl_context *ssl,
                                                      unsigned char *buf,
                                                      unsigned char *end,
                                                      size_t *olen )
{
    unsigned char *p = (unsigned char*)buf;
    size_t selected_identity;

    *olen = 0;

    if( ssl->handshake->psk == NULL )
    {
        /* We shouldn't have called this extension writer unless we've
         * chosen to use a PSK. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding pre_shared_key extension" ) );

    if( end < p || ( end - p ) < 6 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Extension Type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_PRE_SHARED_KEY, p, 0 );

    /* Extension Length */
    MBEDTLS_PUT_UINT16_BE( 2, p, 2 );

    /* NOTE: This will need to be adjusted once we support multiple PSKs
     *       being offered by the client. */
    selected_identity = 0;

    /* Write selected_identity */
    MBEDTLS_PUT_UINT16_BE( selected_identity, p, 4 );

    *olen = 6;

    MBEDTLS_SSL_DEBUG_MSG( 4, ( "sent selected_identity: %" MBEDTLS_PRINTF_SIZET , selected_identity ) );

    return( 0 );
}
#endif	/* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED  */

#if defined(MBEDTLS_SSL_COOKIE_C)
void mbedtls_ssl_conf_cookies( mbedtls_ssl_config *conf,
                               mbedtls_ssl_cookie_write_t *f_cookie_write,
                               mbedtls_ssl_cookie_check_t *f_cookie_check,
                               void *p_cookie,
                               unsigned int rr_config )
{
    conf->f_cookie_write = f_cookie_write;
    conf->f_cookie_check = f_cookie_check;
    conf->p_cookie = p_cookie;
    conf->rr_config = rr_config;
}
#endif /* MBEDTLS_SSL_COOKIE_C */

#if defined(MBEDTLS_SSL_COOKIE_C)
static int ssl_tls13_parse_cookie_ext( mbedtls_ssl_context *ssl,
                                       const unsigned char *buf,
                                       size_t len )
{
    int ret = 0;
    size_t cookie_len;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "parse cookie extension" ) );

    if( ssl->conf->f_cookie_check != NULL )
    {
        if( len >= 2 )
        {
            cookie_len = MBEDTLS_GET_UINT16_BE( buf, 0 );
            buf += 2;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message - cookie length mismatch" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        if( cookie_len + 2 != len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message - cookie length mismatch" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "Received cookie", buf, cookie_len );

        if( ssl->conf->f_cookie_check( ssl->conf->p_cookie,
                      buf, cookie_len, ssl->cli_id, ssl->cli_id_len ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification failed" ) );
            ret = MBEDTLS_ERR_SSL_HRR_REQUIRED;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification passed" ) );
        }
    }
    else {
        /* TBD: Check under what cases this is appropriate */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification skipped" ) );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_COOKIE_C */



#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
static int ssl_tls13_parse_servername_ext( mbedtls_ssl_context *ssl,
                                           const unsigned char *buf,
                                           size_t len )
{
    int ret;
    size_t servername_list_size, hostname_len;
    const unsigned char *p;

    if( ssl->conf->p_sni == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "No SNI callback configured. Skip SNI parsing." ) );
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Parse ServerName extension" ) );

    servername_list_size = MBEDTLS_GET_UINT16_BE( buf, 0 );
    if( servername_list_size + 2 != len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    p = buf + 2;
    while ( servername_list_size > 0 )
    {
        hostname_len = MBEDTLS_GET_UINT16_BE( p, 1 );
        if( hostname_len + 3 > servername_list_size )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        if( p[0] == MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME )
        {
            ret = ssl->conf->f_sni( ssl->conf->p_sni,
                                   ssl, p + 3, hostname_len );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "sni_wrapper", ret );
                mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                               MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME );
                return( MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME );
            }
            return( 0 );
        }

        servername_list_size -= hostname_len + 3;
        p += hostname_len + 3;
    }

    if( servername_list_size != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    return( 0 );
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */


#if defined(MBEDTLS_ZERO_RTT)
/*
  static int ssl_tls13_parse_early_data_ext( mbedtls_ssl_context *ssl,
  const unsigned char *buf,
  size_t len )
  {
  ( ( void* )ssl );
  ( ( void* )buf );
  return( 0 );
  }
*/
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_tls13_parse_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                                    const unsigned char *buf,
                                                    size_t len )
{
    if( len != 1 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    if( buf[0] >= MBEDTLS_SSL_MAX_FRAG_LEN_INVALID )
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );

    ssl->session_negotiate->mfl_code = buf[0];
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Maximum fragment length = %d", buf[0] ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/* From RFC 8446:
 *
 *   enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
 *   struct {
 *       PskKeyExchangeMode ke_modes<1..255>;
 *   } PskKeyExchangeModes;
 */
static int ssl_tls13_parse_key_exchange_modes_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   size_t len )
{
    size_t ke_modes_len;
    int ke_modes = 0;

    /* Read PSK mode list length (1 Byte) */
    ke_modes_len = *buf++;
    len--;

    /* There's no content after the PSK mode list, to its length
     * must match the total length of the extension. */
    if( ke_modes_len != len )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    /* Currently, there are only two PSK modes, so even without looking
     * at the content, something's wrong if the list has more than 2 items. */
    if( ke_modes_len > 2 )
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );

    while( ke_modes_len-- != 0 )
    {
        switch( *buf )
        {
        case MBEDTLS_SSL_TLS1_3_PSK_MODE_PURE:
            ke_modes |= MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
            break;
        case MBEDTLS_SSL_TLS1_3_PSK_MODE_ECDHE:
            ke_modes |= MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
            break;
        default:
            return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        }
    }

    ssl->handshake->tls13_kex_modes = ke_modes;
    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_SSL_ALPN)
static int ssl_tls13_parse_alpn_ext( mbedtls_ssl_context *ssl,
                                     const unsigned char *buf, size_t len )
{
    const unsigned char *end = buf + len;
    size_t list_len;

    const char **cur_ours;
    const unsigned char *cur_cli;
    size_t cur_cli_len;

    /* If ALPN not configured, just ignore the extension */
    if( ssl->conf->alpn_list == NULL )
        return( 0 );

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     */

    if( len < 2 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    list_len = MBEDTLS_GET_UINT16_BE( buf, 0 );
    if( list_len != len - 2 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    buf += 2;
    len -= 2;

    /* Validate peer's list (lengths) */
    for( cur_cli = buf; cur_cli != end; cur_cli += cur_cli_len )
    {
        cur_cli_len = *cur_cli++;
        if( cur_cli_len > (size_t)( end - cur_cli ) )
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        if( cur_cli_len == 0 )
            return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* Use our order of preference */
    for( cur_ours = ssl->conf->alpn_list; *cur_ours != NULL; cur_ours++ )
    {
        size_t const cur_ours_len = strlen( *cur_ours );
        for( cur_cli = buf; cur_cli != end; cur_cli += cur_cli_len )
        {
            cur_cli_len = *cur_cli++;

            if( cur_cli_len == cur_ours_len &&
                memcmp( cur_cli, *cur_ours, cur_ours_len ) == 0 )
            {
                ssl->alpn_chosen = *cur_ours;
                return( 0 );
            }
        }
    }

    /* If we get hhere, no match was found */
    MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                  MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL );
    return( MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL );
}
#endif /* MBEDTLS_SSL_ALPN */

/*
 *
 * STATE HANDLING: NewSessionTicket message
 *
 */
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

/* Main state-handling entry point; orchestrates the other functions. */
static int ssl_tls13_write_new_session_ticket_process( mbedtls_ssl_context *ssl );

#define SSL_NEW_SESSION_TICKET_SKIP  0
#define SSL_NEW_SESSION_TICKET_WRITE 1

static int ssl_tls13_write_new_session_ticket_coordinate( mbedtls_ssl_context *ssl );

static int ssl_tls13_write_new_session_ticket_write( mbedtls_ssl_context *ssl,
                                                     unsigned char *buf,
                                                     size_t buflen,
                                                     size_t *olen );

/* Update the state after handling the incoming end of early data message. */
static int ssl_tls13_write_new_session_ticket_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */
static int ssl_tls13_write_new_session_ticket_process( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_new_session_ticket_coordinate( ssl ) );

    if( ret == SSL_NEW_SESSION_TICKET_WRITE )
    {
        unsigned char *buf;
        size_t buf_len, msg_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                MBEDTLS_SSL_HS_NEW_SESSION_TICKET, &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_new_session_ticket_write(
                                  ssl, buf, buf_len, &msg_len ) );

        MBEDTLS_SSL_PROC_CHK(
            ssl_tls13_write_new_session_ticket_postprocess( ssl ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                                  ssl, buf_len, msg_len ) );
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK(
            ssl_tls13_write_new_session_ticket_postprocess( ssl ) );
    }

cleanup:

    return( ret );
}

static int ssl_tls13_write_new_session_ticket_coordinate( mbedtls_ssl_context *ssl )
{
    /* Check whether the use of session tickets is enabled */
    if( ssl->conf->session_tickets == 0 )
    {
        return( SSL_NEW_SESSION_TICKET_SKIP );
    }

    return( SSL_NEW_SESSION_TICKET_WRITE );
}


static int ssl_tls13_write_new_session_ticket_postprocess( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET_FLUSH );
    return( 0 );
}

/* This function creates a NewSessionTicket message in the following format:
 *
 * struct {
 *    uint32 ticket_lifetime;
 *    uint32 ticket_age_add;
 *    opaque ticket_nonce<0..255>;
 *    opaque ticket<1..2^16-1>;
 *    Extension extensions<0..2^16-2>;
 * } NewSessionTicket;
 *
 * The ticket inside the NewSessionTicket message is an encrypted container
 * carrying the necessary information so that the server is later able to
 * re-start the communication.
 *
 * The following fields are placed inside the ticket by the
 * f_ticket_write() function:
 *
 *  - creation time (start)
 *  - flags (flags)
 *  - lifetime (ticket_lifetime)
 *  - age add (ticket_age_add)
 *  - key (key)
 *  - key length (key_len)
 *  - ciphersuite (ciphersuite)
 *  - certificate of the peer (peer_cert)
 *
 */
static int ssl_tls13_write_new_session_ticket_write( mbedtls_ssl_context *ssl,
                                                     unsigned char *buf,
                                                     size_t buflen,
                                                     size_t *olen )
{
    int ret;
    size_t tlen;
    size_t ext_len = 0;
    unsigned char *p;
    unsigned char *end = buf + buflen;
    mbedtls_ssl_ciphersuite_t *suite_info;
    int hash_length;
    unsigned char *ticket_lifetime_ptr;

    size_t const total_length = 12 + MBEDTLS_SSL_TICKET_NONCE_LENGTH;
    p = buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write NewSessionTicket msg" ) );

    /* Do we have space for the fixed length part of the ticket */
    if( buflen < total_length )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer for ticket too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    suite_info = (mbedtls_ssl_ciphersuite_t *) ssl->handshake->ciphersuite_info;

    hash_length = mbedtls_hash_size_for_ciphersuite( suite_info );

    if( hash_length == -1 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* In this code the psk key length equals the length of the hash */
    ssl->session->key_len = hash_length;
    ssl->session->ciphersuite = ssl->handshake->ciphersuite_info->id;

    /* Ticket Lifetime
     * (write it later)
     */
    ticket_lifetime_ptr = p;
    p+=4;

    /* Ticket Age Add */
    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                  (unsigned char*) &ssl->session->ticket_age_add,
                                  sizeof( ssl->session->ticket_age_add ) ) != 0 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Failed to generate ticket" ) );
        return( ret );
    }

    MBEDTLS_PUT_UINT32_BE( ssl->session->ticket_age_add, p, 0 );
    p += 4;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->ticket_age_add: %u", ssl->session->ticket_age_add ) );

    /* Ticket Nonce */
    *(p++) = MBEDTLS_SSL_TICKET_NONCE_LENGTH;

    ret = ssl->conf->f_rng( ssl->conf->p_rng, p,
                            MBEDTLS_SSL_TICKET_NONCE_LENGTH );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 3, "ticket_nonce:",
                           p, MBEDTLS_SSL_TICKET_NONCE_LENGTH );

    MBEDTLS_SSL_DEBUG_BUF( 3, "resumption_master_secret",
                           ssl->session->app_secrets.resumption_master_secret,
                           hash_length );

    /* Computer resumption key
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */
    ret = mbedtls_ssl_tls13_hkdf_expand_label(
               mbedtls_psa_translate_md( suite_info->mac ),
               ssl->session->app_secrets.resumption_master_secret,
               hash_length,
               MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( resumption ),
               (const unsigned char *) p,
               MBEDTLS_SSL_TICKET_NONCE_LENGTH,
               ssl->session->key,
               hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the ticket-resumed PSK failed", ret );
        return ( ret );
    }

    p += MBEDTLS_SSL_TICKET_NONCE_LENGTH;

    ssl->session->key_len = hash_length;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Ticket-resumed PSK",
                           ssl->session->key, hash_length );

    /* Ticket */
    ret = ssl->conf->f_ticket_write( ssl->conf->p_ticket,
                                     ssl->session,
                                     p + 2, end,
                                     &tlen,
                                     &ssl->session->ticket_lifetime);
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_ticket_write", ret );
        return( ret );
    }

    /* Ticket lifetime */
    MBEDTLS_PUT_UINT16_BE( ssl->session->ticket_lifetime,
                           ticket_lifetime_ptr, 0 );
    ticket_lifetime_ptr += 4;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->ticket_lifetime: %d",
                               ssl->session->ticket_lifetime ) );

    /* Ticket Length */
    MBEDTLS_PUT_UINT16_BE( tlen, p, 0 );
    p += 2 + tlen;

    /* Ticket Extensions
     *
     * Note: We currently don't have any extensions.
     * Set length to zero.
     */
    MBEDTLS_PUT_UINT16_BE( ext_len, p, 0 );
    p += 2;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "NewSessionTicket (extension_length): %" MBEDTLS_PRINTF_SIZET , ext_len ) );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "NewSessionTicket (ticket length): %" MBEDTLS_PRINTF_SIZET , tlen ) );

    *olen = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 4, "ticket", buf, *olen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write new session ticket" ) );

    return( ret );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

/*
 *
 * STATE HANDLING: Parse End-of-Early Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_tls13_read_end_of_early_data_process( mbedtls_ssl_context *ssl );

#define SSL_END_OF_EARLY_DATA_SKIP   0
#define SSL_END_OF_EARLY_DATA_EXPECT 1

static int ssl_tls13_read_end_of_early_data_coordinate( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_tls13_end_of_early_data_fetch( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_ZERO_RTT */

/* Update the state after handling the incoming end of early data message. */
static int ssl_tls13_read_end_of_early_data_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

int ssl_tls13_read_end_of_early_data_process( mbedtls_ssl_context *ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse end_of_early_data" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_read_end_of_early_data_coordinate( ssl ) );
    if( ret == SSL_END_OF_EARLY_DATA_EXPECT )
    {
#if defined(MBEDTLS_ZERO_RTT)

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_end_of_early_data_fetch( ssl ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps->l4 ) );
#else /* MBEDTLS_SSL_USE_MPS */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_end_of_early_data_fetch( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

        mbedtls_ssl_add_hs_hdr_to_checksum( ssl, MBEDTLS_SSL_HS_END_OF_EARLY_DATA, 0 );

#else /* MBEDTLS_ZERO_RTT */

        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#endif /* MBEDTLS_ZERO_RTT */

    }

    /* Postprocessing step: Update state machine */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_read_end_of_early_data_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse end_of_early_data" ) );
    return( ret );

}

#if defined(MBEDTLS_ZERO_RTT)

#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_tls13_end_of_early_data_fetch( mbedtls_ssl_context *ssl )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps->l4 ) );

    if( ret != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps->l4,
                                                      &msg ) );

    if( msg.type != MBEDTLS_SSL_HS_END_OF_EARLY_DATA ||
        msg.length != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, (
             "Bad EndOfEarlyData message: Type %u (expect %u), "
             "Length %u (expect %u)",
             (unsigned) msg.type, MBEDTLS_SSL_HS_END_OF_EARLY_DATA,
             (unsigned) msg.length, 0 ) );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

cleanup:

    return( ret );
}
#else /* MBEDTLS_SSL_USE_MPS */
static int ssl_tls13_end_of_early_data_fetch( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE        ||
        ssl->in_msg[0]  != MBEDTLS_SSL_HS_END_OF_EARLY_DATA ||
        ssl->in_hslen   != 4 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

#endif /* MBEDTLS_ZERO_RTT */

#if !defined(MBEDTLS_ZERO_RTT)
static int ssl_tls13_read_end_of_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( SSL_END_OF_EARLY_DATA_SKIP );
}
#else /* MBEDTLS_ZERO_RTT */
static int ssl_tls13_read_end_of_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_END_OF_EARLY_DATA_SKIP );

    return( SSL_END_OF_EARLY_DATA_EXPECT );
}
#endif /* MBEDTLS_ZERO_RTT */

static int ssl_tls13_read_end_of_early_data_postprocess( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
    return ( 0 );
}

/*
 *
 * STATE HANDLING: Parse Early Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_tls13_read_early_data_process( mbedtls_ssl_context *ssl );

#define SSL_EARLY_DATA_SKIP   0
#define SSL_EARLY_DATA_EXPECT 1

#if defined(MBEDTLS_ZERO_RTT)
#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_tls13_early_data_fetch( mbedtls_ssl_context *ssl,
                                       mbedtls_mps_reader **reader );
#else
static int ssl_tls13_early_data_fetch( mbedtls_ssl_context *ssl,
                                       unsigned char **buf,
                                       size_t *buflen );
#endif /* MBEDTLS_SSL_USE_MPS */
#endif /* MBEDTLS_ZERO_RTT */

static int ssl_tls13_read_early_data_coordinate( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_ZERO_RTT)
/* Parse early data send by the peer. */
static int ssl_tls13_read_early_data_parse( mbedtls_ssl_context *ssl,
    unsigned char const *buf,
    size_t buflen );
#endif /* MBEDTLS_ZERO_RTT */

/* Update the state after handling the incoming early data message. */
static int ssl_tls13_read_early_data_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

int ssl_tls13_read_early_data_process( mbedtls_ssl_context *ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse early data" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_read_early_data_coordinate( ssl ) );

    if( ret == SSL_EARLY_DATA_EXPECT )
    {
#if defined(MBEDTLS_ZERO_RTT)
        unsigned char *buf;
        size_t buflen;
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_reader *rd;
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_early_data_fetch( ssl, &rd ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_get( rd,
                                                  MBEDTLS_MPS_SIZE_MAX,
                                                  &buf,
                                                  &buflen ) );
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_read_early_data_parse( ssl, buf, buflen ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit( rd ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps->l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_early_data_fetch( ssl, &buf, &buflen ) );
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_read_early_data_parse( ssl, buf, buflen ) );

#endif /* MBEDTLS_SSL_USE_MPS */

        /* No state machine update at this point -- we might receive
         * multiple 0-RTT messages. */

#else /* MBEDTLS_ZERO_RTT */

        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#endif /* MBEDTLS_ZERO_RTT */
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_read_early_data_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse early data" ) );
    return( ret );
}

#if defined(MBEDTLS_ZERO_RTT)
#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_tls13_early_data_fetch( mbedtls_ssl_context *ssl,
                                       mbedtls_mps_reader **rd )
{
    int ret;
    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps->l4 ) );

    if( ret != MBEDTLS_MPS_MSG_APP )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_application( &ssl->mps->l4, rd ) );

cleanup:

    return( ret );
}
#else /* MBEDTLS_SSL_USE_MPS */
static int ssl_tls13_early_data_fetch( mbedtls_ssl_context *ssl,
                                       unsigned char **buf,
                                       size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    *buf    = ssl->in_msg;
    *buflen = ssl->in_hslen;

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */
#endif /* MBEDTLS_ZERO_RTT */

#if !defined(MBEDTLS_ZERO_RTT)
static int ssl_tls13_read_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( SSL_EARLY_DATA_SKIP );
}
#else /* MBEDTLS_ZERO_RTT */
static int ssl_tls13_read_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_EARLY_DATA_SKIP );

    /* Activate early data transform */
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to 0-RTT keys for inbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_set_incoming_keys( &ssl->mps->l4,
                                                   ssl->handshake->epoch_earlydata ) );

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps->l4 ) );
    if( ret != MBEDTLS_MPS_MSG_APP )
        return( SSL_EARLY_DATA_SKIP );

    return( SSL_EARLY_DATA_EXPECT );

cleanup:

    return( ret );

#else /* MBEDTLS_SSL_USE_MPS */

    mbedtls_ssl_set_inbound_transform( ssl, ssl->handshake->transform_earlydata );

    /* Fetching step */
    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    ssl->keep_current_message = 1;

    /* Check for EndOfEarlyData */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
        return( SSL_EARLY_DATA_SKIP );

    return( SSL_EARLY_DATA_EXPECT );

#endif /* MBEDTLS_SSL_USE_MPS */
}

static int ssl_tls13_read_early_data_parse( mbedtls_ssl_context *ssl,
                                            unsigned char const *buf,
                                            size_t buflen )
{
    /* Check whether we have enough buffer space. */
    if( buflen <= ssl->conf->max_early_data )
    {
        /* TODO: We need to check that we're not receiving more 0-RTT
         * than what the ticket allows. */

        /* copy data to staging area */
        memcpy( ssl->early_data_server_buf, buf, buflen );
        /* execute callback to process application data */
        ssl->conf->early_data_callback( ssl, ssl->early_data_server_buf,
                                        buflen );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer too small (recv %" MBEDTLS_PRINTF_SIZET " bytes, buffer %" MBEDTLS_PRINTF_SIZET " bytes)",
                                    buflen, ssl->conf->max_early_data ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT */

static int ssl_tls13_read_early_data_postprocess( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_END_OF_EARLY_DATA );
    return ( 0 );
}

/*
 *
 * STATE HANDLING: ClientHello
 *
 * There are three possible classes of outcomes when parsing the ClientHello:
 *
 * 1) The ClientHello was well-formed and matched the server's configuration.
 *
 *    In this case, the server progresses to sending its ServerHello.
 *
 * 2) The ClientHello was well-formed but didn't match the server's
 *    configuration.
 *
 *    For example, the client might not have offered a key share which
 *    the server supports, or the server might require a cookie.
 *
 *    In this case, the server sends a HelloRetryRequest.
 *
 * 3) The ClientHello was ill-formed
 *
 *    In this case, we abort the handshake.
 *
 */

/*
 * Structure of this message:
 *
 * uint16 ProtocolVersion;
 * opaque Random[32];
 * uint8 CipherSuite[2];    // Cryptographic suite selector
 *
 * struct {
 *      ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *      Random random;
 *      opaque legacy_session_id<0..32>;
 *      CipherSuite cipher_suites<2..2^16-2>;
 *      opaque legacy_compression_methods<1..2^8-1>;
 *      Extension extensions<8..2^16-1>;
 * } ClientHello;
 */

#define SSL_CLIENT_HELLO_OK           0
#define SSL_CLIENT_HELLO_HRR_REQUIRED 1

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_tls13_check_use_0rtt_handshake( mbedtls_ssl_context *ssl )
{
    /* Check if the user has enabled 0-RTT in the config */
    if( !mbedtls_ssl_conf_tls13_0rtt_enabled( ssl ) )
        return( 0 );

    /* Check if the client has indicated the use of 0-RTT */
    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_EARLY_DATA ) == 0 )
        return( 0 );

    /* If the client has indicated the use of 0-RTT but not sent
     * the PSK extensions, that's not conformant (and there's no
     * way to continue from here). */
    if( !ssl_tls13_client_hello_has_psk_extensions( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Client indicated 0-RTT without offering PSK extensions" ) );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* Accept 0-RTT */
    ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_ON;
    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT*/

static int ssl_tls13_parse_client_hello( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t legacy_session_id_len;
    const unsigned char *cipher_suites;
    size_t cipher_suites_len;
    const unsigned char *cipher_suites_end;
    size_t extensions_len;
    const unsigned char *extensions_end;

    const unsigned char *pre_shared_key_ext = NULL;
    size_t pre_shared_key_ext_len = 0;

    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

    int hrr_required = 0;

    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

    /*
     * ClientHello layout:
     *     0  .   1   protocol version
     *     2  .  33   random bytes
     *    34  .  34   session id length ( 1 byte )
     *    35  . 34+x  session id
     *    ..  .  ..   ciphersuite list length ( 2 bytes )
     *    ..  .  ..   ciphersuite list
     *    ..  .  ..   compression alg. list length ( 1 byte )
     *    ..  .  ..   compression alg. list
     *    ..  .  ..   extensions length ( 2 bytes, optional )
     *    ..  .  ..   extensions ( optional )
     */

    /*
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
    if( mbedtls_ssl_read_version( p, ssl->conf->transport ) !=
          MBEDTLS_SSL_VERSION_TLS1_2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return ( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }
    p += 2;

    /*
     * Only support TLS 1.3 currently, temporarily set the version.
     */
    ssl->tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
    /* Store minor version for later use with ticket serialization. */
    ssl->session_negotiate->tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

    /* ---
     *  Random random;
     * ---
     * with Random defined as:
     * opaque Random[32];
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );

    memcpy( &ssl->handshake->randbytes[0], p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    p += MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

    /* ---
     * opaque legacy_session_id<0..32>;
     * ---
     */
    legacy_session_id_len = p[0];
    p++;

    if( legacy_session_id_len > sizeof( ssl->session_negotiate->id ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ssl->session_negotiate->id_len = legacy_session_id_len;
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, session id",
                           p, legacy_session_id_len );
    /*
     * Check we have enough data for the legacy session identifier
     * and the ciphersuite list  length.
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, legacy_session_id_len + 2 );

    memcpy( &ssl->session_negotiate->id[0], p, legacy_session_id_len );
    p += legacy_session_id_len;

    cipher_suites_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check we have enough data for the ciphersuite list, the legacy
     * compression methods and the length of the extensions.
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, cipher_suites_len + 2 + 2 );

   /* ---
    * CipherSuite cipher_suites<2..2^16-2>;
    * ---
    * with CipherSuite defined as:
    * uint8 CipherSuite[2];
    */
    cipher_suites = p;
    cipher_suites_end = p + cipher_suites_len;
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, ciphersuitelist",
                          p, cipher_suites_len );
    /*
     * Search for a matching ciphersuite
     */
    int ciphersuite_match = 0;
    for ( ; p < cipher_suites_end; p += 2 )
    {
        uint16_t cipher_suite;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, cipher_suites_end, 2 );
        cipher_suite = MBEDTLS_GET_UINT16_BE( p, 0 );
        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
        /*
         * Check whether this ciphersuite is valid and offered.
         */
        if( ( mbedtls_ssl_validate_ciphersuite(
            ssl, ciphersuite_info, ssl->tls_version,
            ssl->tls_version ) != 0 ) ||
            !mbedtls_ssl_tls13_cipher_suite_is_offered( ssl, cipher_suite ) )
            continue;

        ssl->session_negotiate->ciphersuite = cipher_suite;
        ssl->handshake->ciphersuite_info = ciphersuite_info;
        ciphersuite_match = 1;

        break;

    }

    if( !ciphersuite_match )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return ( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "selected ciphersuite: %s",
                                ciphersuite_info->name ) );

    p = cipher_suites + cipher_suites_len;
    /* ...
     * opaque legacy_compression_methods<1..2^8-1>;
     * ...
     */
    if( p[0] != 1 || p[1] != MBEDTLS_SSL_COMPRESS_NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad legacy compression method" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return ( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }
    p += 2;

    /* ---
     * Extension extensions<8..2^16-1>;
     * ---
     * with Extension defined as:
     * struct {
     *    ExtensionType extension_type;
     *    opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );
    extensions_end = p + extensions_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", p, extensions_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;
        const unsigned char *extension_data_end;

        /* The PSK extension must be the last in the ClientHello.
         * Fail if we've found it already but haven't yet reached
         * the end of the extension block. */
        if( pre_shared_key_ext != NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        }

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );
        extension_data_end = p + extension_data_len;

        switch( extension_type )
        {
#if defined(MBEDTLS_ECDH_C)
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
#endif /* MBEDTLS_ECDH_C */

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
                if( ret == SSL_TLS1_3_PARSE_KEY_SHARES_EXT_NO_MATCH )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 2, ( "HRR needed " ) );
                    hrr_required = 1;
                    ret = 0;
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

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
            case MBEDTLS_TLS_EXT_SERVERNAME:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found ServerName extension" ) );
                ret = ssl_tls13_parse_servername_ext( ssl, p, extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_parse_servername_ext", ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SERVERNAME;
                break;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_COOKIE_C)
            case MBEDTLS_TLS_EXT_COOKIE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found cookie extension" ) );

                ret = ssl_tls13_parse_cookie_ext( ssl, p, extension_data_len );

                /* if cookie verification failed then we return a hello retry message */
                if( ret == MBEDTLS_ERR_SSL_HRR_REQUIRED )
                {
                    hrr_required = 1;
                }
                else if( ret == 0 ) /* cookie extension present and processed succesfully */
                {
                    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_COOKIE;
                }
                break;
#endif /* MBEDTLS_SSL_COOKIE_C  */

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension" ) );
                /* Delay processing of the PSK identity once we have
                 * found out which algorithms to use. We keep a pointer
                 * to the buffer and the size for later processing.
                 */
                pre_shared_key_ext_len = extension_data_len;
                pre_shared_key_ext = p;

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PRE_SHARED_KEY;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_ZERO_RTT)
            case MBEDTLS_TLS_EXT_EARLY_DATA:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found early_data extension" ) );

                ret = ssl_tls13_parse_early_data_ext( ssl, p, extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_parse_early_data_ext", ret );
                    return( ret );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_EARLY_DATA;
                break;
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found psk key exchange modes extension" ) );

                ret = ssl_tls13_parse_key_exchange_modes_ext( ssl, p, extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_parse_key_exchange_modes_ext", ret );
                    return( ret );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
            case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found max fragment length extension" ) );

                ret = ssl_tls13_parse_max_fragment_length_ext( ssl, p,
                                                               extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_tls13_parse_max_fragment_length_ext" ), ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_MAX_FRAGMENT_LENGTH;
                break;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found alpn extension" ) );

                ret = ssl_tls13_parse_alpn_ext( ssl, p, extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_tls13_parse_alpn_ext" ), ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_ALPN;
                break;
#endif /* MBEDTLS_SSL_ALPN */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                        ( "unknown extension found: %d ( ignoring )",
                          extension_type ) );
        }

        p += extension_data_len;
    }

    /* Update checksum with either
     * - The entire content of the CH message, if no PSK extension is present
     * - The content up to but excluding the PSK extension, if present.
     */
    ssl->handshake->update_checksum( ssl, buf,
                                     ( pre_shared_key_ext != NULL ) ?
                                     pre_shared_key_ext - buf : p - buf );

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

    ssl->handshake->key_exchange = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_NONE;

    if( !ssl_tls13_check_psk_key_exchange( ssl ) &&
        !ssl_tls13_check_ephemeral_key_exchange( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ClientHello message misses mandatory extensions." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION ,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

#if defined(MBEDTLS_ZERO_RTT)
    ret = ssl_tls13_check_use_0rtt_handshake( ssl );
    if( ret != 0 )
        return( ret );
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    /* If we've settled on a PSK-based exchange, parse PSK identity ext */
    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
    {
        ret = mbedtls_ssl_tls13_parse_client_psk_identity_ext(
                  ssl, pre_shared_key_ext, pre_shared_key_ext_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ssl_tls13_parse_client_psk_identity" ),
                                   ret );
            return( ret );
        }
    }
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_SSL_COOKIE_C)
    /* If we failed to see a cookie extension, and we required it through the
     * configuration settings ( rr_config ), then we need to send a HRR msg.
     * Conceptually, this is similiar to having received a cookie that failed
     * the verification check.
     */
    if( ( ssl->conf->rr_config == MBEDTLS_SSL_FORCE_RR_CHECK_ON ) &&
        !( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_COOKIE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Cookie extension missing. Need to send a HRR." ) );
        hrr_required = 1;
    }
#endif /* MBEDTLS_SSL_COOKIE_C */

    if( hrr_required == 1 )
        return( SSL_CLIENT_HELLO_HRR_REQUIRED );

    return( 0 );
}

static int ssl_tls13_postprocess_client_hello( mbedtls_ssl_context *ssl,
                                               int hrr_required )
{
    int ret = 0;
#if defined(MBEDTLS_ZERO_RTT)
    mbedtls_ssl_key_set traffic_keys;
#endif /* MBEDTLS_ZERO_RTT */

    if( ssl->handshake->hello_retry_requests_sent == 0 &&
        ssl->conf->rr_config == MBEDTLS_SSL_FORCE_RR_CHECK_ON )
    {
        hrr_required = 1;
    }

    if( hrr_required )
    {
        /*
         * Create stateless transcript hash for HRR
         */
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Reset transcript for HRR" ) );
        ret = mbedtls_ssl_reset_transcript_for_hrr( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_reset_transcript_for_hrr", ret );
            return( ret );
        }
        mbedtls_ssl_session_reset_msg_layer( ssl, 0 );

        /* Transmit Hello Retry Request */
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HELLO_RETRY_REQUEST );
        return( 0 );
    }

    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
             "mbedtls_ssl_tls13_key_schedule_stage_early", ret );
        return( ret );
    }

#if defined(MBEDTLS_ZERO_RTT)
    if( ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON )
    {
        mbedtls_ssl_transform *transform_earlydata;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Generate 0-RTT keys" ) );

        ret = mbedtls_ssl_tls13_generate_early_data_keys(
            ssl, &traffic_keys );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                      "mbedtls_ssl_tls13_generate_early_data_keys", ret );
            return( ret );
        }

        transform_earlydata = mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
        if( transform_earlydata == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        ret = mbedtls_ssl_tls13_populate_transform(
            transform_earlydata, ssl->conf->endpoint,
            ssl->session_negotiate->ciphersuite, &traffic_keys, ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
            return( ret );
        }

#if !defined(MBEDTLS_SSL_USE_MPS)
        ssl->handshake->transform_earlydata = transform_earlydata;
#else /* MBEDTLS_SSL_USE_MPS */
        /* Register transform with MPS. */
        ret = mbedtls_mps_add_key_material( &ssl->mps->l4,
                                            transform_earlydata,
                                            &ssl->handshake->epoch_earlydata );
        if( ret != 0 )
            return( ret );
#endif /* MBEDTLS_SSL_USE_MPS */
    }

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );

#endif /* MBEDTLS_ZERO_RTT */

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    return( 0 );

}

static int ssl_tls13_process_client_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int hrr_required = 0;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse client hello" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                              ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                              &buf, &buflen ) );

    mbedtls_ssl_add_hs_hdr_to_checksum( ssl, MBEDTLS_SSL_HS_CLIENT_HELLO, buflen );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_parse_client_hello( ssl, buf,
                                                            buf + buflen ) );
    hrr_required = ( ret == SSL_CLIENT_HELLO_HRR_REQUIRED );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "postprocess" ) );
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_client_hello( ssl, hrr_required ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );
    return( ret );
}

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_tls13_write_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                                    unsigned char *buf,
                                                    size_t buflen,
                                                    size_t *olen )
{
    unsigned char *p = buf;

    *olen = 0;

    if( ( ssl->handshake->extensions_present &
          MBEDTLS_SSL_EXT_MAX_FRAGMENT_LENGTH ) == 0 )
    {
        return( 0 );
    }

    if( ssl->session_negotiate->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "adding max_fragment_length extension" ) );

    MBEDTLS_SSL_CHK_BUF_PTR( p, buf + buflen, 5 );

    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH, p, 0 );
    MBEDTLS_PUT_UINT16_BE( 1, p, 2 );
    p[4] = ssl->session_negotiate->mfl_code;

    *olen = 5;

    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_ALPN)
static int ssl_tls13_write_alpn_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf, size_t buflen, size_t *olen )
{
    *olen = 0;

    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_ALPN ) == 0 ||
        ssl->alpn_chosen == NULL )
    {
        return( 0 );
    }

    if( buflen < 7 + strlen( ssl->alpn_chosen ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding alpn extension" ) );
    /*
     * 0 . 1    ext identifier
     * 2 . 3    ext length
     * 4 . 5    protocol list length
     * 6 . 6    protocol name length
     * 7 . 7+n  protocol name
     */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_ALPN, buf, 0 );

    *olen = 7 + strlen( ssl->alpn_chosen );

    MBEDTLS_PUT_UINT16_BE( *olen - 4, buf, 2 );
    MBEDTLS_PUT_UINT16_BE( *olen - 6, buf, 4 );
    buf[6] = MBEDTLS_BYTE_0( *olen - 7 );

    memcpy( buf + 7, ssl->alpn_chosen, *olen - 7 );
    return ( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */

/*
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 */
static int ssl_tls13_prepare_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *server_randbytes =
                    ssl->handshake->randbytes + MBEDTLS_CLIENT_HELLO_RANDOM_LEN;
    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng, server_randbytes,
                                  MBEDTLS_SERVER_HELLO_RANDOM_LEN ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_rng", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes", server_randbytes,
                           MBEDTLS_SERVER_HELLO_RANDOM_LEN );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    return( ret );
}

/*
 * ssl_tls13_write_server_hello_supported_versions_ext ():
 *
 * struct {
 *      ProtocolVersion selected_version;
 * } SupportedVersions;
 */
static int ssl_tls13_write_server_hello_supported_versions_ext(
                                                mbedtls_ssl_context *ssl,
                                                unsigned char *buf,
                                                unsigned char *end,
                                                size_t *out_len )
{
    *out_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, write selected version" ) );

    /* Check if we have space to write the extension:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - selected_version       (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, 6 );

    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS, buf, 0 );

    MBEDTLS_PUT_UINT16_BE( 2, buf, 2 );

    mbedtls_ssl_write_version( buf + 4,
                               ssl->conf->transport,
                               ssl->tls_version );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "supported version: [%04x]",
                                ssl->tls_version ) );

    *out_len = 6;

    return( 0 );
}

/* Generate and export a single key share. For hybrid KEMs, this can
 * be called multiple times with the different components of the hybrid. */
static int ssl_tls13_generate_and_write_key_share( mbedtls_ssl_context *ssl,
                                                   uint16_t named_group,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    *out_len = 0;

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
        ((void) ssl);
        ((void) named_group);
        ((void) buf);
        ((void) end);
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    return( ret );
}

/*
 * ssl_tls13_write_key_share_ext
 *
 * Structure of key_share extension in ServerHello:
 *
 * struct {
 *     NamedGroup group;
 *     opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 * struct {
 *     KeyShareEntry server_share;
 * } KeyShareServerHello;
 */
static int ssl_tls13_write_key_share_ext( mbedtls_ssl_context *ssl,
                                          unsigned char *buf,
                                          unsigned char *end,
                                          size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    uint16_t group = ssl->handshake->offered_group_id;
    unsigned char *server_share = buf + 4;
    size_t key_exchange_length;

    *out_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding key share extension" ) );

    /* Check if we have space for header and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - group                  (2 bytes)
     * - key_exchange_length    (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 8 );
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, p, 0 );
    MBEDTLS_PUT_UINT16_BE( group, server_share, 0 );
    p += 8;

    /* When we introduce PQC-ECDHE hybrids, we'll want to call this
     * function multiple times. */
    ret = ssl_tls13_generate_and_write_key_share(
              ssl, group, server_share + 4, end, &key_exchange_length );
    if( ret != 0 )
        return( ret );
    p += key_exchange_length;
    MBEDTLS_PUT_UINT16_BE( key_exchange_length, server_share + 2, 0 );

    MBEDTLS_PUT_UINT16_BE( p - server_share, buf, 2 );

    *out_len = p - buf;

    return( 0 );
}

static int ssl_tls13_write_hrr_key_share_ext( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *olen )
{
    size_t total_len = 0;

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

    *olen = 0;

    /* For a pure PSK-based ciphersuite there is no key share to declare. */
    if( !mbedtls_ssl_tls13_kex_with_ephemeral( ssl ) )
        return( 0 );

    /* We should only send the key_share extension if the client's initial
     * key share was not acceptable. */
    if( ssl->handshake->offered_group_id != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Skip key_share extension in HRR" ) );
        return( 0 );
    }

    total_len = 6; /* extension header, extension length, NamedGroup value */

    if( (size_t)( end - buf ) < total_len )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    /* Write extension header */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0 );
    /* Write extension length */
    MBEDTLS_PUT_UINT16_BE( 2, buf, 2 );
    buf += 4;

    if( ssl->handshake->hrr_selected_group == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching named group found" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    /* Write selected group */
    MBEDTLS_PUT_UINT16_BE( ssl->handshake->hrr_selected_group, buf, 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "NamedGroup in HRR: %x",
                                ssl->handshake->hrr_selected_group ) );
    *olen = total_len;
    return( 0 );
}

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
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    unsigned char *p_extensions_len;
    size_t output_len;               /* Length of buffer used by function */

    *out_len = 0;

    /* ...
     * ProtocolVersion legacy_version = 0x0303; // TLS 1.2
     * ...
     * with ProtocolVersion defined as:
     * uint16 ProtocolVersion;
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( 0x0303, p, 0 );
    p += 2;

    /* ...
     * Random random;
     * ...
     * with Random defined as:
     * opaque Random[MBEDTLS_SERVER_HELLO_RANDOM_LEN];
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    memcpy( p, &ssl->handshake->randbytes[MBEDTLS_CLIENT_HELLO_RANDOM_LEN],
               MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /* ...
     * opaque legacy_session_id_echo<0..32>;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 + ssl->session_negotiate->id_len );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    if( ssl->session_negotiate->id_len > 0 )
    {
        memcpy( p, &ssl->session_negotiate->id[0],
                ssl->session_negotiate->id_len );
        p += ssl->session_negotiate->id_len;

        MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
    }

    /* ...
     * CipherSuite cipher_suite;
     * ...
     * with CipherSuite defined as:
     * uint8 CipherSuite[2];
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( ssl->session_negotiate->ciphersuite, p, 0 );
    p += 2;
    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "server hello, chosen ciphersuite: %s ( id=%d )",
          mbedtls_ssl_get_ciphersuite_name(
            ssl->session_negotiate->ciphersuite ),
          ssl->session_negotiate->ciphersuite ) );

    /* ...
     * uint8 legacy_compression_method = 0;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    *p++ = 0x0;

    /* ...
     * Extension extensions<6..2^16-1>;
     * ...
     * struct {
     *      ExtensionType extension_type; (2 bytes)
     *      opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p_extensions_len = p;
    p += 2;

    if( ( ret = ssl_tls13_write_server_hello_supported_versions_ext(
                                            ssl, p, end, &output_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET(
            1, "ssl_tls13_write_server_hello_supported_versions_ext", ret );
        return( ret );
    }
    p += output_len;

    if( mbedtls_ssl_tls13_kex_with_ephemeral( ssl ) )
    {
        ret = ssl_tls13_write_key_share_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
    {
        ret = ssl_tls13_write_server_pre_shared_key_ext( ssl, p, end,
                                                         &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    MBEDTLS_PUT_UINT16_BE( p - p_extensions_len - 2, p_extensions_len, 0 );

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello extensions",
                           p_extensions_len, p - p_extensions_len );

    *out_len = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello", buf, *out_len );

    return( ret );
}

static int ssl_tls13_finalize_write_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ret = mbedtls_ssl_tls13_compute_handshake_transform( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
                               "mbedtls_ssl_tls13_compute_handshake_transform",
                               ret );
        return( ret );
    }

    return( ret );
}

static int ssl_tls13_write_server_hello( mbedtls_ssl_context *ssl ) {

    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write server hello" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_server_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                                MBEDTLS_SSL_HS_SERVER_HELLO, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_server_hello_body( ssl, buf,
                                                             buf + buf_len,
                                                             &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_write_server_hello( ssl ) );

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    if( ssl->handshake->ccs_sent > 1 )
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO );
    else
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server hello" ) );
    return( ret );
}

/*
 * Handler for MBEDTLS_SSL_ENCRYPTED_EXTENSIONS
 */

/*
 * struct {
 *    Extension extensions<0..2 ^ 16 - 1>;
 * } EncryptedExtensions;
 *
 */

static int ssl_tls13_prepare_encrypted_extensions( mbedtls_ssl_context *ssl )
{
#if !defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_ssl_set_outbound_transform( ssl, ssl->handshake->transform_handshake );
#else /* MBEDTLS_SSL_USE_MPS */
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* Register transform with MPS. */
    ret = mbedtls_mps_add_key_material( &ssl->mps->l4,
                                        ssl->handshake->transform_handshake,
                                        &ssl->handshake->epoch_handshake );
    if( ret != 0 )
        return( ret );

    ssl->handshake->transform_handshake = NULL;

    /* Use new transform for outgoing data. */
    ret = mbedtls_mps_set_outgoing_keys( &ssl->mps->l4,
                                         ssl->handshake->epoch_handshake );
    if( ret != 0 )
        return( ret );
#endif /* MBEDTLS_SSL_USE_MPS */

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for outbound data" ) );

#if !defined(MBEDTLS_SSL_USE_MPS)
    memset( ssl->out_ctr, 0, 8 );
#endif /* MBEDTLS_SSL_USE_MPS */

    return( 0 );
}

static int ssl_tls13_write_encrypted_extensions_body( mbedtls_ssl_context *ssl,
                                                      unsigned char *buf,
                                                      unsigned char *end,
                                                      size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    size_t extensions_len = 0;
    unsigned char *p_extensions_len;
    size_t output_len;

    *out_len = 0;

    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p_extensions_len = p;
    p += 2;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    ret = ssl_tls13_write_sni_server_ext( ssl, p, end - p, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_ALPN)
    ret = ssl_tls13_write_alpn_ext( ssl, p, end - p, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    ret = ssl_tls13_write_max_fragment_length_ext( ssl, p, end - p, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_ZERO_RTT)
    ret = mbedtls_ssl_tls13_write_early_data_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_ZERO_RTT */

    extensions_len = ( p - p_extensions_len ) - 2;
    MBEDTLS_PUT_UINT16_BE( extensions_len, p_extensions_len, 0 );

    *out_len = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 4, "encrypted extensions", buf, *out_len );

    return( 0 );
}

static int ssl_tls13_write_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write encrypted extension" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_encrypted_extensions( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                       MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_encrypted_extensions_body(
                              ssl, buf, buf + buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    else
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
#endif

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write encrypted extension" ) );
    return( ret );
}

/*
 *
 * Handler for MBEDTLS_SSL_CERTIFICATE_REQUEST
 *
 */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#define SSL_CERTIFICATE_REQUEST_SEND_REQUEST 0
#define SSL_CERTIFICATE_REQUEST_SKIP         1
/* Coordination:
 * Check whether a CertificateRequest message should be written.
 * Returns a negative code on failure, or
 * - SSL_CERTIFICATE_REQUEST_SEND_REQUEST
 * - SSL_CERTIFICATE_REQUEST_SKIP
 * indicating if the writing of the CertificateRequest
 * should be skipped or not.
 */
static int ssl_tls13_certificate_request_coordinate( mbedtls_ssl_context *ssl )
{
    int authmode;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
        authmode = ssl->handshake->sni_authmode;
    else
#endif
        authmode = ssl->conf->authmode;

    if( authmode == MBEDTLS_SSL_VERIFY_NONE )
        return( SSL_CERTIFICATE_REQUEST_SKIP );

    return( SSL_CERTIFICATE_REQUEST_SEND_REQUEST );
}

/*
 * struct {
 *   opaque certificate_request_context<0..2^8-1>;
 *   Extension extensions<2..2^16-1>;
 * } CertificateRequest;
 *
 */
static int ssl_tls13_write_certificate_request_body( mbedtls_ssl_context *ssl,
                                                     unsigned char *buf,
                                                     const unsigned char *end,
                                                     size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    size_t output_len = 0;
    unsigned char *p_extensions_len;

    *out_len = 0;

    /* Check if we have enough space:
     * - certificate_request_context (1 byte)
     * - extensions length           (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 3 );

    /*
     * Write certificate_request_context
     */
    /*
     * We use a zero length context for the normal handshake
     * messages. For post-authentication handshake messages
     * this request context would be set to a non-zero value.
     */
    *p++ = 0x0;

    /*
     * Write extensions
     */
    /* The extensions must contain the signature_algorithms. */
    p_extensions_len = p;
    p += 2;
    ret = mbedtls_ssl_write_sig_alg_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );

    p += output_len;
    MBEDTLS_PUT_UINT16_BE( p - p_extensions_len - 2, p_extensions_len, 0 );

    *out_len = p - buf;

    return( 0 );
}

static int ssl_tls13_write_certificate_request( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate request" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_certificate_request_coordinate( ssl ) );

    if( ret == SSL_CERTIFICATE_REQUEST_SEND_REQUEST )
    {
        unsigned char *buf;
        size_t buf_len, msg_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                MBEDTLS_SSL_HS_CERTIFICATE_REQUEST, &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_certificate_request_body(
                                  ssl, buf, buf + buf_len, &msg_len ) );

        mbedtls_ssl_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST, buf, msg_len );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                                  ssl, buf_len, msg_len ) );
    }
    else if( ret == SSL_CERTIFICATE_REQUEST_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate request" ) );
        ret = 0;
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CERTIFICATE );
cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate request" ) );
    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 * Handler for MBEDTLS_SSL_HELLO_RETRY_REQUEST
 */

static int ssl_tls13_write_hello_retry_request_coordinate( mbedtls_ssl_context *ssl )
{
    if( ssl->handshake->hello_retry_requests_sent > 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Too many HRRs" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    return( 0 );
}

static int ssl_tls13_write_hello_retry_request_body( mbedtls_ssl_context *ssl,
                                                     unsigned char *buf,
                                                     size_t buflen,
                                                     size_t *olen )
{
    int ret;
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    unsigned char *ext_len_byte;
    size_t ext_length;
    size_t total_ext_len = 0;
    unsigned char *extension_start;
    const char magic_hrr_string[32] =
               { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE,
                 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2,
                 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09,
                 0xE2, 0xC8, 0xA8, 0x33 ,0x9C };

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write hello retry request" ) );

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


    /* For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     *
     *  For DTLS 1.3 we use the legacy version number
     *  {254,253}.
     *
     *  In cTLS the version number is elided.
     */
    *p++ = 0x03;
    *p++ = 0x03;
    MBEDTLS_SSL_DEBUG_BUF( 3, "server version", p - 2, 2 );

    /* write magic string (as a replacement for the random value) */
    memcpy( p, &magic_hrr_string[0], 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Random bytes in HelloRetryRequest", p, 32 );
    p += 32;

    /* write legacy_session_id_echo */
    *p++ = (unsigned char) ssl->session_negotiate->id_len;
    memcpy( p, &ssl->session_negotiate->id[0], ssl->session_negotiate->id_len );
    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", p, ssl->session_negotiate->id_len );
    p += ssl->session_negotiate->id_len;

    /* write ciphersuite (2 bytes) */
    MBEDTLS_PUT_UINT16_BE( ssl->session_negotiate->ciphersuite, p, 0 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "ciphersuite", p, 2 );
    p += 2;

    /* write legacy_compression_method (0) */
    *p++ = 0x0;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "legacy compression method: [%d]", *( p-1 ) ) );

    /* write extensions */
    extension_start = p;
    /* Extension starts with a 2 byte length field; we skip it and write it later */
    p += 2;

#if defined(MBEDTLS_SSL_COOKIE_C)

    /* Cookie Extension
     *
     * struct {
     *    opaque cookie<0..2^16-1>;
     * } Cookie;
     *
     */

    /* Write extension header */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_COOKIE, p, 0 );
    p += 2;

    /* Skip writing the extension and the cookie length */
    ext_len_byte = p;
    p += 4;

    /* If we get here, f_cookie_check is not null */
    if( ssl->conf->f_cookie_write == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "inconsistent cookie callbacks" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ( ret = ssl->conf->f_cookie_write( ssl->conf->p_cookie,
                                           &p, end,
                                           ssl->cli_id,
                                           ssl->cli_id_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_cookie_write", ret );
        return( ret );
    }

    ext_length = ( p - ( ext_len_byte + 4 ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Cookie", ext_len_byte + 4, ext_length );

    /* Write extension length */
    MBEDTLS_PUT_UINT16_BE( ext_length + 2, ext_len_byte, 0 );

    /* Write cookie length */
    MBEDTLS_PUT_UINT16_BE( ext_length, ext_len_byte, 2 );

    /* 2 bytes for extension type,
     * 2 bytes for extension length field,
     * 2 bytes for cookie length */
    total_ext_len += ext_length + 6;
#endif /* MBEDTLS_SSL_COOKIE_C */

    /* Add supported_version extension */
    if( ( ret = ssl_tls13_write_server_hello_supported_versions_ext(
                    ssl, p, end, &ext_length ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_server_hello_supported_versions_ext", ret );
        return( ret );
    }

    total_ext_len += ext_length;
    p += ext_length;

    /* Add key_share extension, if necessary */
    ret = ssl_tls13_write_hrr_key_share_ext( ssl, p, end, &ext_length );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_hrr_key_share_ext", ret );
        return( ret );
    }
    total_ext_len += ext_length;
    p += ext_length;

    MBEDTLS_PUT_UINT16_BE( total_ext_len, extension_start, 0 );

    *olen = p - buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write hello retry request" ) );
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
                              ssl, buf, buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );

    ssl->handshake->hello_retry_requests_sent++;

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CCS_AFTER_HRR );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

cleanup:

    return( ret );
}

/*
 * TLS and DTLS 1.3 State Maschine -- server side
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
            ssl->handshake->hello_retry_requests_sent = 0;
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
            ssl->handshake->ccs_sent = 0;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

            break;

            /* ----- READ CLIENT HELLO ----*/

        case MBEDTLS_SSL_CLIENT_HELLO:

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
            ssl->session_negotiate->tls_version = ssl->tls_version;
            ssl->session_negotiate->endpoint = ssl->conf->endpoint;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

            ret = ssl_tls13_process_client_hello( ssl );
            if( ret != 0 )
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_process_client_hello", ret );

            break;

            /* ----- WRITE EARLY APP DATA  ----*/
        case MBEDTLS_SSL_EARLY_APP_DATA:

            ret = ssl_tls13_read_early_data_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_read_early_data_process", ret );
                return ( ret );
            }

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

            /* ----- WRITE CHANGE CIPHER SPEC ----*/

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_SERVER_CCS_AFTER_HRR:
            ret = mbedtls_ssl_tls13_write_change_cipher_spec( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_write_change_cipher_spec", ret );
                return( ret );
            }

            break;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

            /* ----- READ 2nd CLIENT HELLO ----*/
        case MBEDTLS_SSL_SECOND_CLIENT_HELLO:

            ret = ssl_tls13_process_client_hello( ssl );

            switch( ret )
            {
                case 0:
                    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
                    break;
                case MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION:
                    MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                                  MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
                    break;
                case MBEDTLS_ERR_SSL_CONTINUE_PROCESSING:
                    /* Stay in this state */
                    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_CLIENT_HELLO );
                    ret = 0;
                    break;
                default:
                    return( ret );
            }

            break;
            /* ----- WRITE SERVER HELLO ----*/

        case MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_tls13_write_server_hello( ssl );
            if( ret != 0 )
                break;


            break;

            /* ----- WRITE CHANGE CIPHER SPEC ----*/

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO:
            ret = mbedtls_ssl_tls13_write_change_cipher_spec(ssl);
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_write_change_cipher_spec", ret );
                return( ret );
            }

            break;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

            /* ----- WRITE ENCRYPTED EXTENSIONS ----*/

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls13_write_encrypted_extensions( ssl );
            break;

            /* ----- WRITE CERTIFICATE REQUEST ----*/

        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_tls13_write_certificate_request( ssl );
            break;

            /* ----- WRITE SERVER CERTIFICATE ----*/

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = mbedtls_ssl_tls13_write_certificate( ssl );
            break;

            /* ----- WRITE SERVER CERTIFICATE VERIFY ----*/

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = mbedtls_ssl_tls13_write_certificate_verify( ssl );
            break;

            /* ----- WRITE FINISHED ----*/

        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = mbedtls_ssl_tls13_write_finished_message( ssl );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );
            break;

            /* ----- READ CLIENT CERTIFICATE ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = mbedtls_ssl_tls13_process_certificate( ssl );
            if( ret == 0 )
            {
                mbedtls_ssl_handshake_set_state(
                    ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY );
            }
            break;

            /* ----- READ CLIENT CERTIFICATE VERIFY ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
            ret = mbedtls_ssl_tls13_process_certificate_verify( ssl );
            if( ret == 0 )
            {
                mbedtls_ssl_handshake_set_state(
                    ssl, MBEDTLS_SSL_CLIENT_FINISHED );
            }
            break;

        case MBEDTLS_SSL_END_OF_EARLY_DATA:
            ret = ssl_tls13_read_end_of_early_data_process( ssl );
            break;

            /* ----- READ FINISHED ----*/

        case MBEDTLS_SSL_CLIENT_FINISHED:
            ret = mbedtls_ssl_tls13_process_finished_message( ssl );
            if( ret == 0 )
            {
                mbedtls_ssl_handshake_set_state(
                    ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );
            }
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake: done" ) );

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for all traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
            ret = mbedtls_mps_set_incoming_keys( &ssl->mps->l4,
                                                 ssl->epoch_application );
            if( ret != 0 )
                return( ret );

            ret = mbedtls_mps_set_outgoing_keys( &ssl->mps->l4,
                                                 ssl->epoch_application );
            if( ret != 0 )
                return( ret );
#else
            mbedtls_ssl_set_inbound_transform ( ssl, ssl->transform_application );
            mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_application );
#endif /* MBEDTLS_SSL_USE_MPS */

            mbedtls_ssl_tls13_handshake_wrapup( ssl );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET );

            break;

        case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET:

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

            ret = ssl_tls13_write_new_session_ticket_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_new_session_ticket ", ret );
                return( ret );
            }
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

            break;

        case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET_FLUSH:
            ret = mbedtls_ssl_flush_output( ssl );
            if( ret != 0 )
                return( ret );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_TLS1_3 */
