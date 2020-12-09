/*
 *  Messaging layer for use with TLS/DTLS 1.3
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS ( https://tls.mbed.org )
 */

/* This code will be merged into MPS:
 * https://github.com/hanno-arm/mbedtls/tree/mps_implementation/
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "mbedtls/aes.h"
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/hkdf.h"
#include <string.h>

#if defined(MBEDTLS_X509_CRT_PARSE_C) &&                \
    defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

/*
 * Encryption/decryption functions
 */
static int ssl_encrypt_buf( mbedtls_ssl_context *ssl )
{
    mbedtls_cipher_mode_t mode;
    int auth_done = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> encrypt buf" ) );

    if( ssl->transform_out == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

    MBEDTLS_SSL_DEBUG_BUF( 4, "plaintext ( before encryption )",
                           ssl->out_msg, ssl->out_msglen );

    /*
     * Encrypt
     */
#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C) ||  defined(MBEDTLS_CHACHAPOLY_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY )
    {
        int ret;
        size_t enc_msglen, olen;
        unsigned char* enc_msg;
        unsigned char add_data[5];
        size_t add_data_len;
        unsigned char taglen;

        taglen = ssl->handshake->ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* TBD: We need to adjust the additional data calculation for CID use */

            /* Adding the ( fake ) content type to additional data */
            add_data[0] = 23;

            /* Adding the version to additional data */
            add_data[1] = 0xfe;
            add_data[2] = 0xfd;

            /* Adding the length to additional data */
            add_data[3] = ( ( ssl->out_msglen + taglen ) >> 8 ) & 0xFF;
            add_data[4] = ( ssl->out_msglen + taglen ) & 0xFF;

            add_data_len = 5;
        }
        else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        {
            /* Adding the content type to additional data */
            add_data[0] = ssl->out_hdr[0];

            /* Adding the version to additional data */
            add_data[1] = ssl->out_hdr[1];
            add_data[2] = ssl->out_hdr[2];

            /* Adding the length to additional data */
            add_data[3] = ( ( ssl->out_msglen + taglen ) >> 8 ) & 0xFF;
            add_data[4] = ( ssl->out_msglen + taglen ) & 0xFF;

            add_data_len = 5;
        }

        enc_msg = ssl->out_msg;
        enc_msglen = ssl->out_msglen;
        /* We adjust the message length since the authentication tag also consumes space. */
        ssl->out_msglen += taglen;

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "msglen ( %d )", ssl->out_msglen ) );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( before )", ssl->transform_out->iv_enc, ssl->transform_out->ivlen );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( before ):", ssl->transform_out->sequence_number_enc, 12 );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Additional data used", add_data, add_data_len );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Plaintext message:", enc_msg, enc_msglen );

        if( ( ret = mbedtls_cipher_auth_encrypt( &ssl->transform_out->cipher_ctx_enc,
                                                 ssl->transform_out->iv_enc,
                                                 ssl->transform_out->ivlen,
                                                 add_data, add_data_len,
                                                 enc_msg, enc_msglen,
                                                 enc_msg, &olen,
                                                 enc_msg + enc_msglen, taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_encrypt", ret );
            return( ret );
        }

        if( olen != enc_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /* ssl->out_msglen += taglen; */
        auth_done++;

        /* The size of the sequence number varies with DTLS 1.2 and DTLS 1.3,
	 * as well as been encrypted and plaintext payloads.
	 *
	 * Cases for the sequence numbers and epochs:
	 * - DTLS 1.2 plaintext: 48 bit seqnr + 16 bit epoch
	 * - DTLS 1.2 ciphertext: 48 bit seqnr + 16 bit epoch
	 * - DTLS 1.3 plaintext: 48 bit seqnr + 16 bit epoch
	 * - DTLS 1.3 ciphertext: 16 bit or 8 bit seqnr + 2 bit epoch
	 *                        ( encrypted seqnr )
	 */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* For DTLS 1.3 and encrypted payloads only */
        if( ( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM ) &&
            ( ssl->transform_out != NULL ) )
        {
            /* TBD: Need to optimize this code section */

            unsigned char mask[16];
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init( &aes_ctx );

            /* For a working sequence number encryption solution we need 16 or more bytes
             * of encrypted payload. We do a sanity check for the message length.
             */
            if( enc_msglen + taglen < 16 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Sequence number encryption failed - msg payload too short." ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            /* Need to adjust to the key size and algorithm */
            mbedtls_aes_setkey_enc( &aes_ctx, ssl->transform_out->traffic_keys.client_sn_key, 128 );

            /*   Mask = AES-ECB( sn_key, Ciphertext[0..15] ) */
            mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, ssl->out_msg, mask );

            /*  The encrypted sequence number is computed by XORing the leading bytes
             *  of the Mask with the sequence number.
             */
            ssl->out_ctr[0] ^= mask[0];
            ssl->out_ctr[1] ^= mask[1];

            mbedtls_aes_free( &aes_ctx );
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS   */

        if( ( ret = mbedtls_increment_sequence_number( &ssl->transform_out->sequence_number_enc[0], ssl->transform_out->iv_enc, ssl->transform_out->ivlen ) ) != 0 )
        {

            MBEDTLS_SSL_DEBUG_RET( 1, "Error in sequence number processing", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( after )", ssl->transform_out->iv_enc, ssl->transform_out->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( after ):", ssl->transform_out->sequence_number_enc, 12 );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( with tag ): ", enc_msg, ssl->out_msglen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Tag", enc_msg + enc_msglen, taglen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( without tag ): ", enc_msg, ssl->out_msglen - taglen );
    } else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C || MBEDTLS_MODE_CHACHAPOLY  */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= encrypt buf" ) );

    return( 0 );
}

/*
 * Record layer functions
 */

/*
 * Write current record.
 * Uses ssl->out_msgtype, ssl->out_msglen and bytes at ssl->out_msg.
 */
int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl, uint8_t force_flush )
{
    int ret, done = 0;
    size_t dummy_length;
    size_t len = ssl->out_msglen;
    size_t protected_record_size;

    ((void) dummy_length); /* TODO: Guard this appropriately. */

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> write record" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
    {
        ; /* Skip special handshake treatment when resending */
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        if( ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
        {

            if( ssl->out_msg[0] != MBEDTLS_SSL_HS_HELLO_REQUEST &&
                ssl->handshake == NULL && ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            /*
             * TLS / DTLS 1.3 Handshake Message
             *
             * struct {
             *     HandshakeType msg_type;    // handshake type
             *     uint24 length;             // bytes in message
             *     uint16 message_seq;        // DTLS only
             *     uint24 fragment_offset;    // DTLS only
             *     uint24 fragment_length;    // DTLS-required field
             *     select( HandshakeType ) {
             *         case client_hello:          ClientHello;
             *         case server_hello:          ServerHello;
             *         case end_of_early_data:     EndOfEarlyData;
             *         case encrypted_extensions:  EncryptedExtensions;
             *         case certificate_request:   CertificateRequest;
             *         case certificate:           Certificate;
             *         case certificate_verify:    CertificateVerify;
             *         case finished:              Finished;
             *         case new_session_ticket:    NewSessionTicket;
             *         case key_update:            KeyUpdate;
             *     } body;
             * } Handshake;
             *
             */
            /* Add handshake message length */
            ssl->out_msg[1] = (unsigned char)( ( len - 4 ) >> 16 );
            ssl->out_msg[2] = (unsigned char)( ( len - 4 ) >> 8 );
            ssl->out_msg[3] = (unsigned char)( ( len - 4 ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
            /*
             * DTLS has additional fields in the Handshake layer,
             * between the length field and the actual payload:
             *      uint16 message_seq;
             *      uint24 fragment_offset;
             *      uint24 fragment_length;
             */
            if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            {
                /* Make room for the additional DTLS fields */
                memmove( ssl->out_msg + mbedtls_ssl_hs_hdr_len( ssl ), ssl->out_msg + 4, len - 4 );
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
                /* Advancing also the pointer to the pre_shared_key extension ( if used ) */
                if( ( ssl->handshake != NULL ) && ( ssl->handshake->pre_shared_key_pointer != NULL ) )
                {
                    ssl->handshake->pre_shared_key_pointer += 8;
                }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
                len += 8;

                /* Write message_seq and update it */
                if( ssl->out_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET )
                {
                    /* TBD: Here we just fake the sequence number field.
                     * In the future we need to store the sequence number in the
                     * session state ( instead of the handshake state ).
                     */
                    /* Add Handshake sequence number */
                    ssl->out_msg[4] = ( ssl->handshake->out_msg_seq >> 8 ) & 0xFF;
                    ssl->out_msg[5] = ( ssl->handshake->out_msg_seq ) & 0xFF;
                    ++( ssl->handshake->out_msg_seq );
                }
                else
                {
                    /* Add Handshake sequence number */
                    ssl->out_msg[4] = ( ssl->handshake->out_msg_seq >> 8 ) & 0xFF;
                    ssl->out_msg[5] = ( ssl->handshake->out_msg_seq ) & 0xFF;
                    ++( ssl->handshake->out_msg_seq );
                }

                /* We don't fragment, so frag_offset = 0 and frag_len = len */
                memset( ssl->out_msg + 6, 0x00, 3 );

                /* Copying the length field back into the shifted area */
                memcpy( ssl->out_msg + 9, ssl->out_msg + 1, 3 );
            }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED) && defined(MBEDTLS_SSL_CLI_C)
            /* We need to patch the psk binder by
             * re-running the function to get the correct length information for the extension.
             * But: we only do that when in ClientHello state and when using a PSK mode
             */
            if( ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
                &&
                ( ssl->state == MBEDTLS_SSL_CLIENT_HELLO )
                &&
                ( ssl->handshake->extensions_present & PRE_SHARED_KEY_EXTENSION )
                &&
                ( ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_ALL ||
                  ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_ALL ||
                  ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_KE ||
                  ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_DHE_KE ) ) {

                mbedtls_ssl_write_pre_shared_key_ext( ssl, ssl->handshake->ptr_to_psk_ext, &ssl->out_msg[len], &dummy_length, 1 );
            }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED && MBEDTLS_SSL_CLI_C */

            /* For post-handshake messages we do not need to update the hash anymore */
            if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            {
                MBEDTLS_SSL_DEBUG_MSG( 5, ( "--- Update Checksum ( mbedtls_ssl_write_record )" ) );
                ssl->handshake->update_checksum( ssl, ssl->out_msg, len );
            }
        }
    }

    if( ssl->transform_out != NULL )
    {
        /* We add the ContentType to the end of the payload
           and fake the one visible from the outside. */
        ssl->out_msg[len] = ssl->out_msgtype;
        len++;
    }

    /* Keep local `len` and ssl->out_msglen in sync */
    ssl->out_msglen = len;

    /* Save handshake and CCS messages for resending */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state != MBEDTLS_SSL_RETRANS_SENDING &&
        ( ssl->out_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC ||
          ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE ) )
    {
        if( ( ret = ssl_flight_append( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_flight_append", ret );
            return( ret );
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_write != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_write( )" ) );

        ret = mbedtls_ssl_hw_record_write( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_write", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

    if( !done )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        size_t i=0;

        /*
         *
         * --- DTLS 1.3 Record Layer Header ---
         *
         * struct {
         * 		ContentType type;
         * 		ProtocolVersion legacy_record_version;
         * 		uint16 epoch = 0         // DTLS field
         * 		uint48 sequence_number;  // DTLS field
         * 		uint16 length;
         * 		opaque fragment[DTLSPlaintext.length];
         * } DTLSPlaintext;

         * struct {
         * 		opaque content[DTLSPlaintext.length];
         *      ContentType type;
         * 		uint8 zeros[length_of_padding];
         * } DTLSInnerPlaintext;
         *
         * struct {
         * 		opaque unified_hdr[variable];
         * 		opaque encrypted_record[length];
         * } DTLSCiphertext;
         *
         *    0 1 2 3 4 5 6 7
         *    +-+-+-+-+-+-+-+-+
         *    |0|0|1|C|S|L|E E|
         *    +-+-+-+-+-+-+-+-+
         *    | Connection ID |   Legend:
         *    | ( if any,      |
         *    /  length as    /   C   - CID present
         *    |  negotiated )  |   S   - Sequence number length
         *    +-+-+-+-+-+-+-+-+   L   - Length present
         *    |  8 or 16 bit  |   E   - Epoch
         *    |Sequence Number|
         *    +-+-+-+-+-+-+-+-+
         *    | 16 bit Length |
         *    | ( if present )  |
         *    +-+-+-+-+-+-+-+-+
         *
         */

        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {

            if( ssl->transform_out == NULL )
            {
                /* Plaintext DTLS payload */

                /* Set ContentType  */
                ssl->out_hdr[0] = ssl->out_msgtype;

                /* Write version */
                mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                                           ssl->conf->transport, ssl->out_hdr + 1 );

                /* Write epoch */
                ssl->out_buf[3] = ( char )( ssl->out_epoch >> 8 ) & 0xFF;
                ssl->out_buf[4] = ( char )( ssl->out_epoch ) & 0xFF;

                /* Write sequence number */
                /* TBD */

                /* Write Length */
                ssl->out_len[0] = (unsigned char)( len >> 8 );
                ssl->out_len[1] = (unsigned char)( len );
            }
            else
            {
                /* Encrypted DTLS payload */

                /* Set flags in unified header */
                ssl->out_hdr[0] = MBEDTLS_SSL_UNIFIED_HDR_PREAMBLE_3;

#if defined(MBEDTLS_CID)
                if( ssl->out_cid_len > 0 )
                {

                    ssl->out_hdr[0] = ssl->out_hdr[0] | MBEDTLS_SSL_UNIFIED_HDR_CID;

                    /* Write the CID of the outgoing datagram */
                    memcpy( &ssl->out_hdr[1], ssl->out_cid, ssl->out_cid_len );
                    i += ssl->out_cid_len;
                }
#endif /* MBEDTLS_CID */

                /* Write epoch */
                switch ( ssl->out_epoch % 4 ) {

                    case 0: /* clear epoch 1 and 2 */
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1 );
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2 );
                        break;

                    case 1: /* Set epoch 1 and clear epoch 2 */
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1;
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2 );
                        break;

                    case 2: /* Clear epoch 1 and set epoch 2 */
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1 );
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2;
                        break;

                    case 3: /* Set epoch 1 and 2 */
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1;
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2;
                }

                /* Write 16 bit sequence number */
                ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_SNR;

                /* Change pointer for where to store the sequence number fields */
                ssl->out_ctr = &ssl->out_hdr[1 + i];

                /* Write 16 bit length */
                ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_LEN;
                ssl->out_hdr[3 + i] = (unsigned char)( len >> 8 );
                ssl->out_hdr[4 + i] = (unsigned char)( len );

                /* Change pointer to length field */
                ssl->out_len = &ssl->out_hdr[3 + i];

                /* Change pointer to message contents */
                ssl->out_msg = &ssl->out_hdr[3 + i + 2];
            }
        }
        else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        {

            /*
             *
             * --- TLS 1.3 Record Layer Header ---
             *
             *	struct {
             *  	ContentType type;
             *		ProtocolVersion record_version = { 3, 1 };
             * 		uint16 length;
             * 		opaque fragment[TLSPlaintext.length];
             * } TLSPlaintext;
             */

            /* Set ContentType  */
            if( ssl->transform_out != NULL )
            {
                /* In case of TLS 1.3 for encrypted payloads we claim that we are
                 * sending application data but in reality we are using
                 * an encrypted handshake message.
                 */
                ssl->out_hdr[0] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
            }
            else
            {
                ssl->out_hdr[0] = ssl->out_msgtype;
            }

            /* TLS 1.3 re-uses the version {3, 4} in the ClientHello, Serverhello,
             * etc. but the record layer uses {3, 3} ( or {3,1} for compatibility reasons,
             * and hence we need to patch it.
             */
            mbedtls_ssl_write_version( 3, 3, ssl->conf->transport, ssl->out_hdr + 1 );

            /* Write Length */
            ssl->out_len[0] = (unsigned char)( len >> 8 );
            ssl->out_len[1] = (unsigned char)( len );
        }

        if( ssl->transform_out != NULL )
        {
            if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_encrypt_buf", ret );
                return( ret );
            }

            len = ssl->out_msglen;
            ssl->out_len[0] = (unsigned char)( len >> 8 );
            ssl->out_len[1] = (unsigned char)( len );
        }

        /* Calculate the number of bytes we have to put on the wire */
        protected_record_size = mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_OUT,
                                                     ssl->transform_out ) + len;

        ssl->out_left += protected_record_size;
        ssl->out_hdr  += protected_record_size;
        mbedtls_ssl_update_out_pointers( ssl, ssl->transform_out );

        if( ssl->transform_out != NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                                        "version = [%d:%d], msglen = %d",
                                        ssl->out_msgtype, ssl->major_ver, ssl->minor_ver,
                                        ( ssl->out_len[0] << 8 ) | ssl->out_len[1] ) );
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                                        "version = [%d:%d], msglen = %d",
                                        ssl->out_hdr[0], ssl->out_hdr[1], ssl->out_hdr[2],
                                        ( ssl->out_len[0] << 8 ) | ssl->out_len[1] ) );
        }
    }

    if( force_flush == SSL_FORCE_FLUSH &&
        ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= write record" ) );

    return( 0 );
}

/*
 * Send pending fatal alerts or warnings.
 */
int mbedtls_ssl_handle_pending_alert( mbedtls_ssl_context *ssl )
{
    int ret;

    /* Send alert if requested */
    if( ssl->send_alert != 0 )
    {
        ret = mbedtls_ssl_send_alert_message( ssl,
                                              ssl->send_alert,
                                              ssl->alert_type );
        if( ret != 0 )
            return( ret );
    }

    ssl->send_alert = 0;
    ssl->alert_type = 0;
    return( 0 );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS_C */
