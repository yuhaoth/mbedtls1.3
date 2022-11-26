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
#include "mbedtls/platform.h"
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

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET_REMOVED)
#include "mbedtls/ssl_ticket.h"
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET_REMOVED */

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


static const mbedtls_ssl_ciphersuite_t *ssl_tls13_validate_peer_ciphersuite(
                                      mbedtls_ssl_context *ssl,
                                      unsigned int cipher_suite )
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    if( ! mbedtls_ssl_tls13_cipher_suite_is_offered( ssl, cipher_suite ) )
        return( NULL );

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
    if( ( mbedtls_ssl_validate_ciphersuite( ssl, ciphersuite_info,
                                            ssl->tls_version,
                                            ssl->tls_version ) != 0 ) )
    {
        return( NULL );
    }
    return( ciphersuite_info );
}

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/* From RFC 8446:
 *
 *   enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
 *   struct {
 *       PskKeyExchangeMode ke_modes<1..255>;
 *   } PskKeyExchangeModes;
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_key_exchange_modes_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    const unsigned char *p = buf;
    size_t ke_modes_len;
    int ke_modes = 0;

    /* Read ke_modes length (1 Byte) */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    ke_modes_len = *p++;
    /* Currently, there are only two PSK modes, so even without looking
     * at the content, something's wrong if the list has more than 2 items. */
    if( ke_modes_len > 2 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, ke_modes_len );

    while( ke_modes_len-- != 0 )
    {
        switch( *p++ )
        {
        case MBEDTLS_SSL_TLS1_3_PSK_MODE_PURE:
            ke_modes |= MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "Found PSK KEX MODE" ) );
            break;
        case MBEDTLS_SSL_TLS1_3_PSK_MODE_ECDHE:
            ke_modes |= MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "Found PSK_EPHEMERAL KEX MODE" ) );
            break;
        default:
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                          MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
            return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        }
    }

    ssl->handshake->tls13_kex_modes = ke_modes;
    return( 0 );
}

#define SSL_TLS1_3_OFFERED_PSK_NOT_MATCH   1
#define SSL_TLS1_3_OFFERED_PSK_MATCH       0
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_offered_psks_check_identity_match(
               mbedtls_ssl_context *ssl,
               const unsigned char *identity,
               size_t identity_len,
               int *psk_type )
{
    *psk_type = MBEDTLS_SSL_TLS1_3_PSK_EXTERNAL;
    /* Check identity with external configured function */
    if( ssl->conf->f_psk != NULL )
    {
        if( ssl->conf->f_psk(
                ssl->conf->p_psk, ssl, identity, identity_len ) == 0 )
        {
            return( SSL_TLS1_3_OFFERED_PSK_MATCH );
        }
        return( SSL_TLS1_3_OFFERED_PSK_NOT_MATCH );
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "identity", identity, identity_len );
    /* Check identity with pre-configured psk */
    if( ssl->conf->psk_identity != NULL &&
        identity_len == ssl->conf->psk_identity_len &&
        mbedtls_ct_memcmp( ssl->conf->psk_identity,
                            identity, identity_len ) == 0 )
    {
        mbedtls_ssl_set_hs_psk( ssl, ssl->conf->psk, ssl->conf->psk_len );
        return( SSL_TLS1_3_OFFERED_PSK_MATCH );
    }

    return( SSL_TLS1_3_OFFERED_PSK_NOT_MATCH );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_offered_psks_check_binder_match( mbedtls_ssl_context *ssl,
                                                      const unsigned char *binder,
                                                      size_t binder_len,
                                                      int psk_type,
                                                      psa_algorithm_t psk_hash_alg )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    unsigned char transcript[PSA_HASH_MAX_SIZE];
    size_t transcript_len;
    unsigned char *psk;
    size_t psk_len;
    unsigned char server_computed_binder[PSA_HASH_MAX_SIZE];

    /* Get current state of handshake transcript. */
    ret = mbedtls_ssl_get_handshake_transcript(
              ssl, mbedtls_hash_info_md_from_psa( psk_hash_alg ),
              transcript, sizeof( transcript ), &transcript_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_export_handshake_psk( ssl, &psk, &psk_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_create_psk_binder( ssl, psk_hash_alg,
                                               psk, psk_len, psk_type,
                                               transcript,
                                               server_computed_binder );
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_free( (void*)psk );
#endif
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "PSK binder calculation failed." ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder ( computed ): ",
                           server_computed_binder, transcript_len );
    MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder ( received ): ", binder, binder_len );

    if( mbedtls_ct_memcmp( server_computed_binder, binder, binder_len ) == 0 )
    {
        return( SSL_TLS1_3_OFFERED_PSK_MATCH );
    }

    mbedtls_platform_zeroize( server_computed_binder,
                              sizeof( server_computed_binder ) );
    return( SSL_TLS1_3_OFFERED_PSK_NOT_MATCH );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_select_ciphersuite_for_psk(
               mbedtls_ssl_context *ssl,
               const unsigned char *cipher_suites,
               const unsigned char *cipher_suites_end,
               uint16_t *selected_ciphersuite,
               const mbedtls_ssl_ciphersuite_t **selected_ciphersuite_info )
{
    psa_algorithm_t psk_hash_alg = PSA_ALG_SHA_256;

    *selected_ciphersuite = 0;
    *selected_ciphersuite_info = NULL;

    /* RFC 8446, page 55.
     *
     * For externally established PSKs, the Hash algorithm MUST be set when the
     * PSK is established or default to SHA-256 if no such algorithm is defined.
     *
     */

    /*
     * Search for a matching ciphersuite
     */
    for ( const unsigned char *p = cipher_suites;
          p < cipher_suites_end; p += 2 )
    {
        uint16_t cipher_suite;
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

        cipher_suite = MBEDTLS_GET_UINT16_BE( p, 0 );
        ciphersuite_info = ssl_tls13_validate_peer_ciphersuite( ssl,
                                                                cipher_suite );
        if( ciphersuite_info == NULL )
            continue;

        /* MAC of selected ciphersuite MUST be same with PSK binder if exist.
         * Otherwise, client should reject.
         */
        if( psk_hash_alg == mbedtls_psa_translate_md( ciphersuite_info->mac ) )
        {
            *selected_ciphersuite = cipher_suite;
            *selected_ciphersuite_info = ciphersuite_info;
            return( 0 );
        }
    }
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "No matched ciphersuite" ) );
    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_select_ciphersuite_for_resumption(
               mbedtls_ssl_context *ssl,
               const unsigned char *cipher_suites,
               const unsigned char *cipher_suites_end,
               mbedtls_ssl_session *session,
               uint16_t *selected_ciphersuite,
               const mbedtls_ssl_ciphersuite_t **selected_ciphersuite_info )
{
    ((void) ssl);
    ((void) session);
    ((void) cipher_suites);
    ((void) cipher_suites_end);
    *selected_ciphersuite = 0;
    *selected_ciphersuite_info = NULL;
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

/* Parser for pre_shared_key extension in client hello
 *    struct {
 *        opaque identity<1..2^16-1>;
 *        uint32 obfuscated_ticket_age;
 *    } PskIdentity;
 *
 *    opaque PskBinderEntry<32..255>;
 *
 *    struct {
 *        PskIdentity identities<7..2^16-1>;
 *        PskBinderEntry binders<33..2^16-1>;
 *    } OfferedPsks;
 *
 *    struct {
 *        select (Handshake.msg_type) {
 *            case client_hello: OfferedPsks;
 *            ....
 *        };
 *    } PreSharedKeyExtension;
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_pre_shared_key_ext( mbedtls_ssl_context *ssl,
                                               const unsigned char *pre_shared_key_ext,
                                               const unsigned char *pre_shared_key_ext_end,
                                               const unsigned char *ciphersuites,
                                               const unsigned char *ciphersuites_end )
{
    const unsigned char *identities = pre_shared_key_ext;
    const unsigned char *p_identity_len;
    size_t identities_len;
    const unsigned char *identities_end;
    const unsigned char *binders;
    const unsigned char *p_binder_len;
    size_t binders_len;
    const unsigned char *binders_end;
    int matched_identity = -1;
    int identity_id = -1;

    MBEDTLS_SSL_DEBUG_BUF( 3, "pre_shared_key extension",
                           pre_shared_key_ext,
                           pre_shared_key_ext_end - pre_shared_key_ext );

    /* identities_len       2 bytes
     * identities_data   >= 7 bytes
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( identities, pre_shared_key_ext_end, 7 + 2 );
    identities_len = MBEDTLS_GET_UINT16_BE( identities, 0 );
    p_identity_len = identities + 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p_identity_len, pre_shared_key_ext_end,
                                  identities_len );
    identities_end = p_identity_len + identities_len;

    /* binders_len     2  bytes
     * binders      >= 33 bytes
     */
    binders = identities_end;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( binders, pre_shared_key_ext_end, 33 + 2 );
    binders_len = MBEDTLS_GET_UINT16_BE( binders, 0 );
    p_binder_len = binders + 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p_binder_len, pre_shared_key_ext_end, binders_len );
    binders_end = p_binder_len + binders_len;

    ssl->handshake->update_checksum( ssl, pre_shared_key_ext,
                                     identities_end - pre_shared_key_ext );

    while( p_identity_len < identities_end && p_binder_len < binders_end )
    {
        const unsigned char *identity;
        size_t identity_len;
        const unsigned char *binder;
        size_t binder_len;
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        int psk_type;
        uint16_t cipher_suite;
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p_identity_len, identities_end, 2 + 1 + 4 );
        identity_len = MBEDTLS_GET_UINT16_BE( p_identity_len, 0 );
        identity = p_identity_len + 2;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( identity, identities_end, identity_len + 4 );
        p_identity_len += identity_len + 6;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p_binder_len, binders_end, 1 + 32 );
        binder_len = *p_binder_len;
        binder = p_binder_len + 1;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( binder, binders_end, binder_len );
        p_binder_len += binder_len + 1;

        identity_id++;
        if( matched_identity != -1 )
            continue;

        ret = ssl_tls13_offered_psks_check_identity_match(
                                    ssl, identity, identity_len, &psk_type );
        if( ret != SSL_TLS1_3_OFFERED_PSK_MATCH )
            continue;

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "found matched identity" ) );
        switch( psk_type )
        {
            case MBEDTLS_SSL_TLS1_3_PSK_EXTERNAL:
                ret = ssl_tls13_select_ciphersuite_for_psk(
                            ssl, ciphersuites, ciphersuites_end,
                            &cipher_suite, &ciphersuite_info );
                break;
            case MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION:
                ret = ssl_tls13_select_ciphersuite_for_resumption(
                            ssl, ciphersuites, ciphersuites_end, NULL,
                            &cipher_suite, &ciphersuite_info );
                break;
            default:
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if( ret != 0 )
        {
            /* See below, no cipher_suite available, abort handshake */
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            MBEDTLS_SSL_DEBUG_RET(
                2, "ssl_tls13_select_ciphersuite", ret );
            return( ret );
        }

        ret = ssl_tls13_offered_psks_check_binder_match(
                  ssl, binder, binder_len, psk_type,
                  mbedtls_psa_translate_md( ciphersuite_info->mac ) );
        if( ret != SSL_TLS1_3_OFFERED_PSK_MATCH )
        {
            /* For security reasons, the handshake should be aborted when we
             * fail to validate a binder value. See RFC 8446 section 4.2.11.2
             * and appendix E.6. */
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "Invalid binder." ) );
            MBEDTLS_SSL_DEBUG_RET( 1,
                "ssl_tls13_offered_psks_check_binder_match" , ret );
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            return( ret );
        }

        matched_identity = identity_id;

        /* Update handshake parameters */
        ssl->session_negotiate->ciphersuite = cipher_suite;
        ssl->handshake->ciphersuite_info = ciphersuite_info;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "overwrite ciphersuite: %04x - %s",
                                    cipher_suite, ciphersuite_info->name ) );

    }

    if( p_identity_len != identities_end || p_binder_len != binders_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "pre_shared_key extesion decode error" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* Update the handshake transcript with the binder list. */
    ssl->handshake->update_checksum( ssl,
                                     identities_end,
                                     (size_t)( binders_end - identities_end ) );
    if( matched_identity == -1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "No matched PSK or ticket." ) );
        return( MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY );
    }

    ssl->handshake->selected_identity = (uint16_t)matched_identity;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Pre shared key found" ) );

    return( 0 );
}

/*
 * struct {
 *   select ( Handshake.msg_type ) {
 *      ....
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

    *olen = 0;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if( mbedtls_svc_key_id_is_null( ssl->handshake->psk_opaque ) )
#else
    if( ssl->handshake->psk == NULL )
#endif
    {
        /* We shouldn't have called this extension writer unless we've
         * chosen to use a PSK. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding pre_shared_key extension" ) );
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );

    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_PRE_SHARED_KEY, p, 0 );
    MBEDTLS_PUT_UINT16_BE( 2, p, 2 );

    MBEDTLS_PUT_UINT16_BE( ssl->handshake->selected_identity, p, 4 );

    *olen = 6;

    MBEDTLS_SSL_DEBUG_MSG( 4, ( "sent selected_identity: %u",
                                ssl->handshake->selected_identity ) );

    return( 0 );
}

#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

/* From RFC 8446:
 *   struct {
 *          ProtocolVersion versions<2..254>;
 *   } SupportedVersions;
 */
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_supported_groups_ext( mbedtls_ssl_context *ssl,
                                                 const unsigned char *buf,
                                                 const unsigned char *end )
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

        MBEDTLS_SSL_DEBUG_MSG( 2,
                               ( "got named group: %s(%04x)",
                                 mbedtls_ssl_named_group_to_str( named_group ),
                                 named_group ) );

        if( ! mbedtls_ssl_named_group_is_offered( ssl, named_group ) ||
            ! mbedtls_ssl_named_group_is_supported( named_group ) ||
            ssl->handshake->hrr_selected_group != 0 )
        {
            continue;
        }

        MBEDTLS_SSL_DEBUG_MSG( 2,
                               ( "add named group %s(%04x) into received list.",
                                 mbedtls_ssl_named_group_to_str( named_group ),
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
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_key_shares_ext( mbedtls_ssl_context *ssl,
                                           const unsigned char *buf,
                                           const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char const *p = buf;
    unsigned char const *client_shares_end;
    size_t client_shares_len;

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

    while( p < client_shares_end )
    {
        uint16_t group;
        size_t key_exchange_len;
        const unsigned char *key_exchange;

        /*
         * struct {
         *    NamedGroup group;
         *    opaque key_exchange<1..2^16-1>;
         * } KeyShareEntry;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, client_shares_end, 4 );
        group = MBEDTLS_GET_UINT16_BE( p, 0 );
        key_exchange_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;
        key_exchange = p;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, client_shares_end, key_exchange_len );
        p += key_exchange_len;

        /* Continue parsing even if we have already found a match,
         * for input validation purposes.
         */
        if( ! mbedtls_ssl_named_group_is_offered( ssl, group ) ||
            ! mbedtls_ssl_named_group_is_supported( group ) ||
            ssl->handshake->offered_group_id != 0 )
        {
            continue;
        }

        /*
         * For now, we only support ECDHE groups.
         */
        if( mbedtls_ssl_tls13_named_group_is_ecdhe( group ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH group: %s (%04x)",
                                        mbedtls_ssl_named_group_to_str( group ),
                                        group ) );
            ret = mbedtls_ssl_tls13_read_public_ecdhe_share(
                      ssl, key_exchange - 2, key_exchange_len + 2 );
            if( ret != 0 )
                return( ret );

        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Unrecognized NamedGroup %u",
                                        (unsigned) group ) );
            continue;
        }

        ssl->handshake->offered_group_id = group;
    }


    if( ssl->handshake->offered_group_id == 0 )
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

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_client_hello_has_exts( mbedtls_ssl_context *ssl,
                                            int exts_mask )
{
    int masked = ssl->handshake->extensions_present & exts_mask;
    return( masked == exts_mask );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_client_hello_has_exts_for_ephemeral_key_exchange(
        mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts(
                ssl,
                MBEDTLS_SSL_EXT_SUPPORTED_GROUPS |
                MBEDTLS_SSL_EXT_KEY_SHARE        |
                MBEDTLS_SSL_EXT_SIG_ALG ) );
}

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_client_hello_has_exts_for_psk_key_exchange(
               mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts(
                ssl,
                MBEDTLS_SSL_EXT_PRE_SHARED_KEY          |
                MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_client_hello_has_exts_for_psk_ephemeral_key_exchange(
               mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts(
                ssl,
                MBEDTLS_SSL_EXT_SUPPORTED_GROUPS        |
                MBEDTLS_SSL_EXT_KEY_SHARE               |
                MBEDTLS_SSL_EXT_PRE_SHARED_KEY          |
                MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_check_ephemeral_key_exchange( mbedtls_ssl_context *ssl )
{
    return( mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) &&
            ssl_tls13_client_hello_has_exts_for_ephemeral_key_exchange( ssl ) );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_check_psk_key_exchange( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    return( mbedtls_ssl_conf_tls13_psk_enabled( ssl ) &&
            mbedtls_ssl_tls13_psk_enabled( ssl ) &&
            ssl_tls13_client_hello_has_exts_for_psk_key_exchange( ssl ) );
#else
    ((void) ssl);
    return( 0 );
#endif
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_check_psk_ephemeral_key_exchange( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    return( mbedtls_ssl_conf_tls13_psk_ephemeral_enabled( ssl ) &&
            mbedtls_ssl_tls13_psk_ephemeral_enabled( ssl ) &&
            ssl_tls13_client_hello_has_exts_for_psk_ephemeral_key_exchange( ssl ) );
#else
    ((void) ssl);
    return( 0 );
#endif
}

static int ssl_tls13_determine_key_exchange_mode( mbedtls_ssl_context *ssl )
{
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
     *  1 ) (EC)DHE-PSK Mode ( psk_ephemeral )
     *  2 ) Certificate Mode ( ephemeral )
     *  3 ) Plain PSK Mode ( psk )
     */

    ssl->handshake->key_exchange_mode = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_NONE;

    if( ssl_tls13_check_psk_ephemeral_key_exchange( ssl ) )
    {
        ssl->handshake->key_exchange_mode =
            MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "key exchange mode: psk_ephemeral" ) );
    }
    else
    if( ssl_tls13_check_ephemeral_key_exchange( ssl ) )
    {
        ssl->handshake->key_exchange_mode =
            MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "key exchange mode: ephemeral" ) );
    }
    else
    if( ssl_tls13_check_psk_key_exchange( ssl ) )
    {
        ssl->handshake->key_exchange_mode =
            MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "key exchange mode: psk" ) );
    }
    else
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

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_read_end_of_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( SSL_END_OF_EARLY_DATA_SKIP );
}
#else /* MBEDTLS_ZERO_RTT */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_read_end_of_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_END_OF_EARLY_DATA_SKIP );

    return( SSL_END_OF_EARLY_DATA_EXPECT );
}
#endif /* MBEDTLS_ZERO_RTT */

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_read_end_of_early_data_postprocess( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to handshake keys for inbound traffic" ) );
#if defined(MBEDTLS_SSL_USE_MPS)
    int ret = mbedtls_mps_set_incoming_keys( &ssl->mps->l4,
                                             ssl->handshake->epoch_handshake );
    if( ret != 0 )
        return( ret );
#else
        mbedtls_ssl_set_inbound_transform( ssl, ssl->handshake->transform_handshake );
#endif /* MBEDTLS_SSL_USE_MPS */

    if( ssl->handshake->certificate_request_sent )
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "skip parse certificate" ) );
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "skip parse certificate verify" ) );
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );
    }

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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_read_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( SSL_EARLY_DATA_SKIP );
}
#else /* MBEDTLS_ZERO_RTT */
MBEDTLS_CHECK_RETURN_CRITICAL
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

MBEDTLS_CHECK_RETURN_CRITICAL
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

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_read_early_data_postprocess( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_END_OF_EARLY_DATA );
    return ( 0 );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/*
 * Pick best ( private key, certificate chain ) pair based on the signature
 * algorithms supported by the client.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_pick_key_cert( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert, *key_cert_list;
    const uint16_t *sig_alg = ssl->handshake->received_sig_algs;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_key_cert != NULL )
        key_cert_list = ssl->handshake->sni_key_cert;
    else
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
        key_cert_list = ssl->conf->key_cert;

    if( key_cert_list == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "server has no certificate" ) );
        return( -1 );
    }

    for( ; *sig_alg != MBEDTLS_TLS1_3_SIG_NONE; sig_alg++ )
    {
        for( key_cert = key_cert_list; key_cert != NULL;
             key_cert = key_cert->next )
        {
            MBEDTLS_SSL_DEBUG_CRT( 3, "certificate (chain) candidate",
                                   key_cert->cert );

            /*
            * This avoids sending the client a cert it'll reject based on
            * keyUsage or other extensions.
            */
            if( mbedtls_x509_crt_check_key_usage(
                    key_cert->cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE ) != 0 ||
                mbedtls_x509_crt_check_extended_key_usage(
                    key_cert->cert, MBEDTLS_OID_SERVER_AUTH,
                    MBEDTLS_OID_SIZE( MBEDTLS_OID_SERVER_AUTH ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "certificate mismatch: "
                                       "(extended) key usage extension" ) );
                continue;
            }

            MBEDTLS_SSL_DEBUG_MSG( 3,
                                   ( "ssl_tls13_pick_key_cert:"
                                     "check signature algorithm %s [%04x]",
                                     mbedtls_ssl_sig_alg_to_str( *sig_alg ),
                                     *sig_alg ) );
            if( mbedtls_ssl_tls13_check_sig_alg_cert_key_match(
                                            *sig_alg, &key_cert->cert->pk ) )
            {
                ssl->handshake->key_cert = key_cert;
                MBEDTLS_SSL_DEBUG_MSG( 3,
                                       ( "ssl_tls13_pick_key_cert:"
                                         "selected signature algorithm"
                                         " %s [%04x]",
                                         mbedtls_ssl_sig_alg_to_str( *sig_alg ),
                                         *sig_alg ) );
                MBEDTLS_SSL_DEBUG_CRT(
                        3, "selected certificate (chain)",
                        ssl->handshake->key_cert->cert );
                return( 0 );
            }
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ssl_tls13_pick_key_cert:"
                                "no suitable certificate found" ) );
    return( -1 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C &&
          MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

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
MBEDTLS_CHECK_RETURN_CRITICAL
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
    if( !ssl_tls13_client_hello_has_exts_for_psk_key_exchange( ssl ) )
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

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_client_hello( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t legacy_session_id_len;
    size_t cipher_suites_len;
    const unsigned char *cipher_suites_end;
    size_t extensions_len;
    const unsigned char *extensions_end;
    int hrr_required = 0;

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    const unsigned char *cipher_suites;
    const unsigned char *pre_shared_key_ext = NULL;
    const unsigned char *pre_shared_key_ext_end = NULL;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

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
     * Minimal length ( with everything empty and extensions omitted ) is
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
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET_REMOVED)
    /* Store minor version for later use with ticket serialization. */
    ssl->session_negotiate->tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET_REMOVED */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    /* Store minor version for later use with ticket serialization. */
    ssl->session_negotiate->tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
    ssl->session_negotiate->endpoint = ssl->conf->endpoint;
#endif

    /* ...
     * Random random;
     * ...
     * with Random defined as:
     * opaque Random[32];
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );

    memcpy( &ssl->handshake->randbytes[0], p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    p += MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

    /* ...
     * opaque legacy_session_id<0..32>;
     * ...
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
     * and the ciphersuite list length.
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, legacy_session_id_len + 2 );

    memcpy( &ssl->session_negotiate->id[0], p, legacy_session_id_len );
    p += legacy_session_id_len;

    cipher_suites_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check we have enough data for the ciphersuite list, the legacy
     * compression methods and the length of the extensions.
     *
     * cipher_suites                cipher_suites_len bytes
     * legacy_compression_methods                   2 bytes
     * extensions_len                               2 bytes
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, cipher_suites_len + 2 + 2 );

   /* ...
    * CipherSuite cipher_suites<2..2^16-2>;
    * ...
    * with CipherSuite defined as:
    * uint8 CipherSuite[2];
    */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    cipher_suites = p;
#endif
    cipher_suites_end = p + cipher_suites_len;
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, ciphersuitelist",
                          p, cipher_suites_len );

    /*
     * Search for a matching ciphersuite
     */
    for ( ; p < cipher_suites_end; p += 2 )
    {
        uint16_t cipher_suite;
        const mbedtls_ssl_ciphersuite_t* ciphersuite_info;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, cipher_suites_end, 2 );

        cipher_suite = MBEDTLS_GET_UINT16_BE( p, 0 );
        ciphersuite_info = ssl_tls13_validate_peer_ciphersuite(
                               ssl,cipher_suite );
        if( ciphersuite_info == NULL )
            continue;

        ssl->session_negotiate->ciphersuite = cipher_suite;
        ssl->handshake->ciphersuite_info = ciphersuite_info;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "selected ciphersuite: %04x - %s",
                                    cipher_suite,
                                    ciphersuite_info->name ) );
    }

    if( ssl->handshake->ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return ( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

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

    /* ...
     * Extension extensions<8..2^16-1>;
     * ...
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

        /* RFC 8446, page 57
         *
         * The "pre_shared_key" extension MUST be the last extension in the
         * ClientHello (this facilitates implementation as described below).
         * Servers MUST check that it is the last extension and otherwise fail
         * the handshake with an "illegal_parameter" alert.
         */
        if( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY )
        {
            MBEDTLS_SSL_DEBUG_MSG(
                3, ( "pre_shared_key is not last extension." ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );
        extension_data_end = p + extension_data_len;

        switch( extension_type )
        {
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
            case MBEDTLS_TLS_EXT_SERVERNAME:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found ServerName extension" ) );
                ret = mbedtls_ssl_parse_server_name_ext( ssl, p,
                                                         extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET(
                            1, "mbedtls_ssl_parse_servername_ext", ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SERVERNAME;
                break;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_ECDH_C)
            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported group extension" ) );

                /* Supported Groups Extension
                 *
                 * When sent by the client, the "supported_groups" extension
                 * indicates the named groups which the client supports,
                 * ordered from most preferred to least preferred.
                 */
                ret = ssl_tls13_parse_supported_groups_ext(
                          ssl, p, extension_data_end );
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
                ret = ssl_tls13_parse_key_shares_ext(
                          ssl, p, extension_data_end );
                if( ret == SSL_TLS1_3_PARSE_KEY_SHARES_EXT_NO_MATCH )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 2, ( "HRR needed " ) );
                    hrr_required = 1;
                }

                if( ret < 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET(
                        1, "ssl_tls13_parse_key_shares_ext", ret );
                    return( ret );
                }

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

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found psk key exchange modes extension" ) );

                ret = ssl_tls13_parse_key_exchange_modes_ext(
                          ssl, p, extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET(
                        1, "ssl_tls13_parse_key_exchange_modes_ext", ret );
                    return( ret );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension" ) );
                if( ( ssl->handshake->extensions_present &
                      MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) == 0 )
                {
                    MBEDTLS_SSL_PEND_FATAL_ALERT(
                        MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                        MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
                    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
                }
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
                /* Delay processing of the PSK identity once we have
                 * found out which algorithms to use. We keep a pointer
                 * to the buffer and the size for later processing.
                 */
                pre_shared_key_ext = p;
                pre_shared_key_ext_end = extension_data_end;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PRE_SHARED_KEY;
                break;

#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found alpn extension" ) );

                ret = mbedtls_ssl_parse_alpn_ext( ssl, p, extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET(
                            1, ( "mbedtls_ssl_parse_alpn_ext" ), ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_ALPN;
                break;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found signature_algorithms extension" ) );

                ret = mbedtls_ssl_parse_sig_alg_ext(
                          ssl, p, extension_data_end );
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

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                        ( "unknown extension found: %d ( ignoring )",
                          extension_type ) );
        }

        p += extension_data_len;
    }

#if defined(MBEDTLS_DEBUG_C)
    /* List all the extensions we have received */
    ssl_tls13_debug_print_client_hello_exts( ssl );
#endif /* MBEDTLS_DEBUG_C */

    mbedtls_ssl_add_hs_hdr_to_checksum( ssl,
                                        MBEDTLS_SSL_HS_CLIENT_HELLO,
                                        p - buf );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* Update checksum with either
     * - The entire content of the CH message, if no PSK extension is present
     * - The content up to but excluding the PSK extension, if present.
     */
    /* If we've settled on a PSK-based exchange, parse PSK identity ext */
    if( mbedtls_ssl_tls13_some_psk_enabled( ssl ) &&
        mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) &&
        ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY ) )
    {
        ssl->handshake->update_checksum( ssl, buf,
                                         pre_shared_key_ext - buf );
        ret = ssl_tls13_parse_pre_shared_key_ext( ssl,
                                                  pre_shared_key_ext,
                                                  pre_shared_key_ext_end,
                                                  cipher_suites,
                                                  cipher_suites_end );
        if( ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY )
        {
            ssl->handshake->extensions_present &= ~MBEDTLS_SSL_EXT_PRE_SHARED_KEY;
        }
        else if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_tls13_parse_pre_shared_key_ext" ),
                                   ret );
            return( ret );
        }
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
    {
        ssl->handshake->update_checksum( ssl, buf, p - buf );
    }

    ret = ssl_tls13_determine_key_exchange_mode( ssl );
    if( ret < 0 )
        return( ret );

    mbedtls_ssl_optimize_checksum( ssl, ssl->handshake->ciphersuite_info );

    return( hrr_required ? SSL_CLIENT_HELLO_HRR_REQUIRED : SSL_CLIENT_HELLO_OK );
}

/* Update the handshake state machine */

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_postprocess_client_hello( mbedtls_ssl_context* ssl )
{
    int ret = 0;
#if defined(MBEDTLS_ZERO_RTT)
    mbedtls_ssl_key_set traffic_keys;
#endif /* MBEDTLS_ZERO_RTT */

    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
             "mbedtls_ssl_tls13_key_schedule_stage_early", ret );
        return( ret );
    }

#if defined(MBEDTLS_ZERO_RTT)
    ret = ssl_tls13_check_use_0rtt_handshake( ssl );
    if( ret != 0 )
        return( ret );

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

    /*
     * Server certificate selection
     */
    if( ssl->conf->f_cert_cb && ( ret = ssl->conf->f_cert_cb( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_cert_cb", ret );
        return( ret );
    }
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    ssl->handshake->sni_name = NULL;
    ssl->handshake->sni_name_len = 0;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

    return( 0 );
}

/*
 * Main entry point from the state machine; orchestrates the otherfunctions.
 */

MBEDTLS_CHECK_RETURN_CRITICAL
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

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_parse_client_hello( ssl, buf,
                                                            buf + buflen ) );
    hrr_required = ( ret == SSL_CLIENT_HELLO_HRR_REQUIRED );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    if( hrr_required )
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HELLO_RETRY_REQUEST );
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "postprocess final client hello" ) );
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_client_hello( ssl ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );

cleanup:
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );
    return( ret );
}

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
MBEDTLS_CHECK_RETURN_CRITICAL
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

/*
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 */
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
MBEDTLS_CHECK_RETURN_CRITICAL
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

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "server hello, write selected_group: %s (%04x)",
                                mbedtls_ssl_named_group_to_str( group ),
                                group ) );

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

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_hrr_key_share_ext( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len )
{
    uint16_t selected_group = ssl->handshake->hrr_selected_group;
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

    /*
     * For a pure PSK key exchange, there is no group to agree upon. The purpose
     * of the HRR is then to transmit a cookie to force the client to demonstrate
     * reachability at their apparent network address (primarily useful for DTLS).
     */
    if( ! mbedtls_ssl_tls13_key_exchange_mode_with_ephemeral( ssl ) )
        return( 0 );

    /* We should only send the key_share extension if the client's initial
     * key share was not acceptable. */
    if( ssl->handshake->offered_group_id != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Skip key_share extension in HRR" ) );
        return( 0 );
    }

    if( selected_group == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching named group found" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    /* Check if we have enough space:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - selected_group         (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, 6 );

    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0 );
    MBEDTLS_PUT_UINT16_BE( 2, buf, 2 );
    MBEDTLS_PUT_UINT16_BE( selected_group, buf, 4 );

    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "HRR selected_group: %s (%x)",
            mbedtls_ssl_named_group_to_str( selected_group ),
            selected_group ) );

    *out_len = 6;

    return( 0 );
}

#if defined(MBEDTLS_SSL_COOKIE_C)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_cookie_ext( mbedtls_ssl_context *ssl,
                                       unsigned char *buf,
                                       unsigned char *end,
                                       size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    unsigned char *p_extension_data_len;
    size_t cookie_len;

    *out_len = 0;

    if( ssl->conf->f_cookie_write == NULL )
        return( 0 );

    /* Cookie Extension
     *
     * struct {
     *    opaque cookie<0..2^16-1>;
     * } Cookie;
     *
     * Create stateless transcript hash for HRR
     */

    /*
     * extension type    2 bytes
     * extension length  2 bytes
     * cookie length     2 bytes
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_COOKIE, p, 0 );
    p_extension_data_len = p + 2;
    p += 6;

    if( ( ret = ssl->conf->f_cookie_write( ssl->conf->p_cookie,
                                           &p, end,
                                           ssl->cli_id,
                                           ssl->cli_id_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_cookie_write", ret );
        return( ret );
    }

    cookie_len = p - ( p_extension_data_len + 4 );

    MBEDTLS_PUT_UINT16_BE( cookie_len + 2, p_extension_data_len, 0 );
    MBEDTLS_PUT_UINT16_BE( cookie_len, p_extension_data_len, 2 );

    *out_len = cookie_len + 6;

    return( 0 );
}
#endif /* MBEDTLS_SSL_COOKIE_C */

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
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_server_hello_body( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len,
                                              int is_hrr )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    unsigned char *p_extensions_len;
    size_t output_len;

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
    if( is_hrr )
    {
        memcpy( p, mbedtls_ssl_tls13_hello_retry_request_magic,
                MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    }
    else
    {
        memcpy( p, &ssl->handshake->randbytes[MBEDTLS_CLIENT_HELLO_RANDOM_LEN],
                MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    }
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
    *p++ = MBEDTLS_SSL_COMPRESS_NULL;

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

    if( mbedtls_ssl_tls13_key_exchange_mode_with_ephemeral( ssl ) )
    {
        if( is_hrr )
            ret = ssl_tls13_write_hrr_key_share_ext( ssl, p, end, &output_len );
        else
            ret = ssl_tls13_write_key_share_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if( mbedtls_ssl_tls13_key_exchange_mode_with_psk( ssl ) )
    {
        ret = ssl_tls13_write_server_pre_shared_key_ext( ssl, p, end, &output_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_server_pre_shared_key_ext",
                                   ret );
            return( ret );
        }
        p += output_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_SSL_COOKIE_C)
    if( is_hrr )
    {
        ret = ssl_tls13_write_cookie_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif /* MBEDTLS_SSL_COOKIE_C */

    MBEDTLS_PUT_UINT16_BE( p - p_extensions_len - 2, p_extensions_len, 0 );

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello extensions",
                           p_extensions_len, p - p_extensions_len );

    *out_len = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello", buf, *out_len );

    return( ret );
}

MBEDTLS_CHECK_RETURN_CRITICAL
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

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write server hello" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_server_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                                MBEDTLS_SSL_HS_SERVER_HELLO, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_server_hello_body( ssl, buf,
                                                             buf + buf_len,
                                                             &msg_len,
                                                             0 ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_write_server_hello( ssl ) );

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    /* The server sends a dummy change_cipher_spec record immediately
     * after its first handshake message. This may either be after
     * a ServerHello or a HelloRetryRequest.
     */
    mbedtls_ssl_handshake_set_state(
            ssl, MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server hello" ) );
    return( ret );
}


/*
 * Handler for MBEDTLS_SSL_HELLO_RETRY_REQUEST
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_prepare_hello_retry_request( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if( ssl->handshake->hello_retry_request_count > 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Too many HRRs" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

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

    return( 0 );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_hello_retry_request( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write hello retry request" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_hello_retry_request( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg(
                              ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                              &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_server_hello_body( ssl, buf,
                                                             buf + buf_len,
                                                             &msg_len,
                                                             1 ) );
    mbedtls_ssl_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_SERVER_HELLO, buf, msg_len );


    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg( ssl, buf_len,
                                                            msg_len ) );

    ssl->handshake->hello_retry_request_count++;

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    /* The server sends a dummy change_cipher_spec record immediately
     * after its first handshake message. This may either be after
     * a ServerHello or a HelloRetryRequest.
     */
    mbedtls_ssl_handshake_set_state(
            ssl, MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

cleanup:
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write hello retry request" ) );
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

MBEDTLS_CHECK_RETURN_CRITICAL
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

MBEDTLS_CHECK_RETURN_CRITICAL
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

    ((void) ssl);
    ((void) ret);
    ((void) output_len);

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    ret = ssl_tls13_write_sni_server_ext( ssl, p, end - p, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_ALPN)
    ret = mbedtls_ssl_write_alpn_ext( ssl, p, end, &output_len );
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

MBEDTLS_CHECK_RETURN_CRITICAL
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
    if( mbedtls_ssl_tls13_key_exchange_mode_with_psk( ssl ) )
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
MBEDTLS_CHECK_RETURN_CRITICAL
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
    {
        ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_SKIP_VERIFY;
        return( SSL_CERTIFICATE_REQUEST_SKIP );
    }

    ssl->handshake->certificate_request_sent = 1;

    return( SSL_CERTIFICATE_REQUEST_SEND_REQUEST );
}

/*
 * struct {
 *   opaque certificate_request_context<0..2^8-1>;
 *   Extension extensions<2..2^16-1>;
 * } CertificateRequest;
 *
 */
MBEDTLS_CHECK_RETURN_CRITICAL
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

MBEDTLS_CHECK_RETURN_CRITICAL
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

/*
 * Handler for MBEDTLS_SSL_SERVER_CERTIFICATE
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_server_certificate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( ( ssl_tls13_pick_key_cert( ssl ) != 0 ) ||
          mbedtls_ssl_own_cert( ssl ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "No certificate available." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    ret = mbedtls_ssl_tls13_write_certificate( ssl );
    if( ret != 0 )
        return( ret );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CERTIFICATE_VERIFY
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_certificate_verify( mbedtls_ssl_context *ssl )
{
    int ret = mbedtls_ssl_tls13_write_certificate_verify( ssl );
    if( ret != 0 )
        return( ret );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 * Handler for MBEDTLS_SSL_SERVER_FINISHED
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_server_finished( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ssl_tls13_write_finished_message( ssl );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_compute_application_transform( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( ret );
    }

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_FINISHED
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_client_finished( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ssl_tls13_process_finished_message( ssl );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_generate_resumption_master_secret( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
            "mbedtls_ssl_tls13_generate_resumption_master_secret ", ret );
    }

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_HANDSHAKE_WRAPUP
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_handshake_wrapup( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ssl_tls13_handshake_wrapup( ssl );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_NEW_SESSION_TICKET );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
#endif
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_NEW_SESSION_TICKET
 */
#define SSL_NEW_SESSION_TICKET_SKIP  0
#define SSL_NEW_SESSION_TICKET_WRITE 1
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_new_session_ticket_coordinate( mbedtls_ssl_context *ssl )
{
    /* Check whether the use of session tickets is enabled */
    if( ssl->conf->f_ticket_write == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "new session ticket is not enabled" ) );
        return( SSL_NEW_SESSION_TICKET_SKIP );
    }

    return( SSL_NEW_SESSION_TICKET_WRITE );
}

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_prepare_new_session_ticket( mbedtls_ssl_context *ssl,
                                                 unsigned char *ticket_nonce,
                                                 size_t ticket_nonce_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_session *session = ssl->session;
    mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    psa_algorithm_t psa_hash_alg;
    int hash_length;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> prepare NewSessionTicket msg" ) );

#if defined(MBEDTLS_HAVE_TIME)
    session->start = mbedtls_time( NULL );
#endif

    /* Generate ticket_age_add */
    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                  (unsigned char *) &session->ticket_age_add,
                                  sizeof( session->ticket_age_add ) ) != 0 ) )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "generate_ticket_age_add", ret );
        return( ret );
    }
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket_age_add: %u",
                                (unsigned int)session->ticket_age_add ) );

    /* Generate ticket_nonce */
    ret = ssl->conf->f_rng( ssl->conf->p_rng, ticket_nonce, ticket_nonce_size );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "generate_ticket_nonce", ret );
        return( ret );
    }
    MBEDTLS_SSL_DEBUG_BUF( 3, "ticket_nonce:",
                           ticket_nonce, ticket_nonce_size );

    ciphersuite_info =
                (mbedtls_ssl_ciphersuite_t *) ssl->handshake->ciphersuite_info;
    psa_hash_alg = mbedtls_psa_translate_md( ciphersuite_info->mac );
    hash_length = PSA_HASH_LENGTH( psa_hash_alg );
    if( hash_length == -1 ||
        (size_t)hash_length > sizeof( session->resumption_key ) )
    {
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* In this code the psk key length equals the length of the hash */
    session->resumption_key_len = hash_length;
    session->ciphersuite = ciphersuite_info->id;

    /* Compute resumption key
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */
    ret = mbedtls_ssl_tls13_hkdf_expand_label(
               psa_hash_alg,
               session->app_secrets.resumption_master_secret,
               hash_length,
               MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( resumption ),
               ticket_nonce,
               ticket_nonce_size,
               session->resumption_key,
               hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2,
                               "Creating the ticket-resumed PSK failed",
                               ret );
        return ( ret );
    }
    MBEDTLS_SSL_DEBUG_BUF( 3, "Ticket-resumed PSK",
                           session->resumption_key,
                           session->resumption_key_len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "resumption_master_secret",
                           session->app_secrets.resumption_master_secret,
                           hash_length );

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
 *  - age add (ticket_age_add)
 *  - key (key)
 *  - key length (key_len)
 *  - ciphersuite (ciphersuite)
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_new_session_ticket_body( mbedtls_ssl_context *ssl,
                                                    unsigned char *buf,
                                                    unsigned char *end,
                                                    size_t *out_len,
                                                    unsigned char *ticket_nonce,
                                                    size_t ticket_nonce_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    mbedtls_ssl_session *session = ssl->session;
    size_t ticket_len;
    uint32_t ticket_lifetime;

    *out_len = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write NewSessionTicket msg" ) );

    /*
     *    ticket_lifetime   4 bytes
     *    ticket_age_add    4 bytes
     *    ticket_nonce      1 + ticket_nonce_size bytes
     *    ticket            >=2 bytes
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 4 + 4 + 1 + ticket_nonce_size + 2 );

    /* Generate ticket and ticket_lifetime */
    ret = ssl->conf->f_ticket_write( ssl->conf->p_ticket,
                                     session,
                                     p + 9 + ticket_nonce_size + 2,
                                     end,
                                     &ticket_len,
                                     &ticket_lifetime);
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "write_ticket", ret );
        return( ret );
    }
    /* RFC 8446 4.6.1
     *  ticket_lifetime:  Indicates the lifetime in seconds as a 32-bit
     *      unsigned integer in network byte order from the time of ticket
     *      issuance.  Servers MUST NOT use any value greater than
     *      604800 seconds (7 days).  The value of zero indicates that the
     *      ticket should be discarded immediately.  Clients MUST NOT cache
     *      tickets for longer than 7 days, regardless of the ticket_lifetime,
     *      and MAY delete tickets earlier based on local policy.  A server
     *      MAY treat a ticket as valid for a shorter period of time than what
     *      is stated in the ticket_lifetime.
     */
    ticket_lifetime %= 604800;
    MBEDTLS_PUT_UINT32_BE( ticket_lifetime, p, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket_lifetime: %u",
                                ( unsigned int )ticket_lifetime ) );

    /* Write ticket_age_add */
    MBEDTLS_PUT_UINT32_BE( session->ticket_age_add, p, 4 );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket_age_add: %u",
                                ( unsigned int )session->ticket_age_add ) );

    /* Write ticket_nonce */
    p[8] = ( unsigned char )ticket_nonce_size;
    if( ticket_nonce_size > 0 )
    {
        memcpy( p + 9, ticket_nonce, ticket_nonce_size );
    }
    p += 9 + ticket_nonce_size;

    /* Write ticket */
    MBEDTLS_PUT_UINT16_BE( ticket_len, p, 0 );
    p += 2;
    MBEDTLS_SSL_DEBUG_BUF( 4, "ticket", p, ticket_len);
    p += ticket_len;

    /* Ticket Extensions
     *
     * Note: We currently don't have any extensions.
     * Set length to zero.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( 0, p, 0 );
    p += 2;

    *out_len = p - buf;
    MBEDTLS_SSL_DEBUG_BUF( 4, "ticket", buf, *out_len );
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write new session ticket" ) );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_NEW_SESSION_TICKET
 */
static int ssl_tls13_write_new_session_ticket( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_new_session_ticket_coordinate( ssl ) );

    if( ret == SSL_NEW_SESSION_TICKET_WRITE )
    {
        unsigned char ticket_nonce[MBEDTLS_SSL_TLS1_3_TICKET_NONCE_LENGTH];
        unsigned char *buf;
        size_t buf_len, msg_len;

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_new_session_ticket(
                                  ssl, ticket_nonce, sizeof( ticket_nonce ) ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                MBEDTLS_SSL_HS_NEW_SESSION_TICKET, &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_new_session_ticket_body(
                                  ssl, buf, buf + buf_len, &msg_len,
                                  ticket_nonce, sizeof( ticket_nonce ) ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                                  ssl, buf_len, msg_len ) );

        mbedtls_ssl_handshake_set_state( ssl,
                                         MBEDTLS_SSL_NEW_SESSION_TICKET_FLUSH );
    }
    else
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
    }

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

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

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
            ssl->handshake->ccs_sent = 0;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */
            break;

            /* ----- READ CLIENT HELLO ----*/

        case MBEDTLS_SSL_CLIENT_HELLO:

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET_REMOVED)
            ssl->session_negotiate->tls_version = ssl->tls_version;
            ssl->session_negotiate->endpoint = ssl->conf->endpoint;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET_REMOVED */

            ret = ssl_tls13_process_client_hello( ssl );
            if( ret != 0 )
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_process_client_hello", ret );
            break;

            /* ----- READ EARLY APP DATA  ----*/

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

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls13_write_encrypted_extensions( ssl );
            break;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_tls13_write_certificate_request( ssl );
            break;

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = ssl_tls13_write_server_certificate( ssl );
            break;

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = ssl_tls13_write_certificate_verify( ssl );
            break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

        /*
         * Injection of dummy-CCS's for middlebox compatibility
         */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST:
            ret = mbedtls_ssl_tls13_write_change_cipher_spec( ssl );
            if( ret == 0 )
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
            break;

        case MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO:
            ret = mbedtls_ssl_tls13_write_change_cipher_spec( ssl );
            if( ret == 0 )
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
            break;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

            /* ----- WRITE FINISHED ----*/

        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = ssl_tls13_write_server_finished( ssl );
            break;

            /* ----- READ CLIENT CERTIFICATE ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = mbedtls_ssl_tls13_process_certificate( ssl );
            if( ret == 0 )
            {
                if( ssl->session_negotiate->peer_cert != NULL )
                {
                    mbedtls_ssl_handshake_set_state(
                        ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY );
                }
                else
                {
                    MBEDTLS_SSL_DEBUG_MSG( 2, ( "skip parse certificate verify" ) );
                    mbedtls_ssl_handshake_set_state(
                        ssl, MBEDTLS_SSL_CLIENT_FINISHED );
                }
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
            ret = ssl_tls13_process_client_finished( ssl );
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            ret = ssl_tls13_handshake_wrapup( ssl );
            break;

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
        case MBEDTLS_SSL_NEW_SESSION_TICKET:
            ret = ssl_tls13_write_new_session_ticket( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1,
                                       "ssl_tls13_write_new_session_ticket ",
                                       ret );
            }
            break;
        case MBEDTLS_SSL_NEW_SESSION_TICKET_FLUSH:
            /* This state is necessary to do the flush of the New Session
             * Ticket message written in MBEDTLS_SSL_NEW_SESSION_TICKET
             * as part of ssl_prepare_handshake_step.
             */
            ret = mbedtls_ssl_flush_output( ssl );
            if( ret != 0 )
                return( ret );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
            break;

#endif /* MBEDTLS_SSL_SESSION_TICKETS */

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_TLS1_3 */
