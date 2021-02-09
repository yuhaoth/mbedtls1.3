/*
 *  Message Processing Stack, Layer 1 implementation
 *
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_MPS_RECORD_LAYER_INTERNAL_H
#define MBEDTLS_MPS_RECORD_LAYER_INTERNAL_H

/*
 * Read/Write of (D)TLS versions
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC void l2_read_version_tls( uint8_t *major, uint8_t *minor,
                                             const unsigned char ver[2] );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC void l2_read_version_dtls( uint8_t *major, uint8_t *minor,
                                              const unsigned char ver[2] );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
MBEDTLS_MPS_STATIC void l2_out_write_version( int major, int minor,
                                  mbedtls_mps_transport_type transport,
                                  unsigned char ver[2] );

/*
 * Management for readers / input queues
 */

/* Initialize readers / input queues. */
MBEDTLS_MPS_STATIC void mps_l2_readers_init( mbedtls_mps_l2 *ctx );
/* Free readers / input queues. */
MBEDTLS_MPS_STATIC void mps_l2_readers_free( mbedtls_mps_l2 *ctx );
/* Get the active reader / input queue, or NULL if there isn't any. */
MBEDTLS_MPS_STATIC
mbedtls_mps_l2_in_internal* mps_l2_readers_get_active( mbedtls_mps_l2 *ctx );
/* Close the active reader / input queue. */
MBEDTLS_MPS_STATIC int mps_l2_readers_close_active( mbedtls_mps_l2 *ctx );
/* Pause the active reader / input queue; this happens if we need more
 * than what's currently available, and we need to accumulate more data
 * from the respective input stream. */
#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int mps_l2_readers_pause_active( mbedtls_mps_l2 *ctx );
#endif /* MBEDTLS_MPS_PROTO_TLS */
/* Check if data is available in one of the readers / input queues. */
MBEDTLS_MPS_STATIC
mbedtls_mps_l2_reader_state mps_l2_readers_active_state( mbedtls_mps_l2 *ctx );
/* Get an unused reader / input queue to manage new incoming data. */
MBEDTLS_MPS_STATIC
mbedtls_mps_l2_in_internal* mps_l2_readers_get_unused( mbedtls_mps_l2 *ctx );
#if defined(MBEDTLS_MPS_PROTO_TLS)
/* The implementation currently maintains a single accumulator for all
 * readers / input queues. Check whether its currently in use. */
MBEDTLS_MPS_STATIC
int mps_l2_readers_accumulator_taken( mbedtls_mps_l2 *ctx );
#endif /* MBEDTLS_MPS_PROTO_TLS */
/* TODO: Document */
MBEDTLS_MPS_INLINE
void mps_l2_reader_slots_changed( mbedtls_mps_l2 *ctx );
/* Match a pair of type and epoch for new incoming data against the set
 * of currently opened readers / input streams. If there's a matching one,
 * return it. If there's one matching the type but with different epoch,
 * fail. */
MBEDTLS_MPS_INLINE
int mps_l2_find_suitable_slot( mbedtls_mps_l2 *ctx,
                               mbedtls_mps_msg_type_t type,
                               mbedtls_mps_epoch_id epoch,
                               mbedtls_mps_l2_in_internal **dst );

/*
 * Reading related
 */

/* Various record header parsing functions
 *
 * These functions fetch and validate record headers for various TLS/DTLS
 * versions from Layer 1 and feed them into the provided record structure.
 *
 * Checks these functions perform:
 * - The epoch is not a valid epoch for incoming records.
 * - The record content type is not valid.
 * - The length field in the record header exceeds the
 *   configured maximum record size.
 * - The datagram didn't contain as much data after
 *   the record header as indicated in the record
 *   header length field.
 * - There wasn't enough space remaining in the datagram
 *   to load a DTLS 1.2 record header.
 * - The record sequence number has been seen before,
 *   so the record is likely duplicated / replayed.
 */
MBEDTLS_MPS_STATIC int l2_in_fetch_record( mbedtls_mps_l2 *ctx, mps_rec *rec );
MBEDTLS_MPS_STATIC int l2_in_fetch_protected_record( mbedtls_mps_l2 *ctx,
                                                     mps_rec *rec );
#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l2_in_fetch_protected_record_tls( mbedtls_mps_l2 *ctx,
                                                         mps_rec *rec );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l2_in_fetch_protected_record_dtls12( mbedtls_mps_l2 *ctx,
                                                            mps_rec *rec );

/* TODO */__attribute__((unused))
MBEDTLS_MPS_STATIC int l2_in_fetch_protected_record_dtls13( mbedtls_mps_l2 *ctx,
                                                            mps_rec *rec );
MBEDTLS_MPS_STATIC int l2_handle_invalid_record( mbedtls_mps_l2 *ctx, int ret );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

MBEDTLS_MPS_STATIC int l2_handle_record_content( mbedtls_mps_l2 *ctx, mps_rec *rec );

/* Signal to the underlying Layer 1 that the last
 * incoming record has been fully processed. */
MBEDTLS_MPS_STATIC int l2_in_release_record( mbedtls_mps_l2 *ctx );

/*
 * Writing related
 */

MBEDTLS_MPS_STATIC int l2_out_prepare_record( mbedtls_mps_l2 *ctx,
                                              mbedtls_mps_epoch_id epoch );
MBEDTLS_MPS_STATIC int l2_out_track_record( mbedtls_mps_l2 *ctx );
MBEDTLS_MPS_STATIC int l2_out_release_record( mbedtls_mps_l2 *ctx,
                                              uint8_t force );
MBEDTLS_MPS_STATIC int l2_out_dispatch_record( mbedtls_mps_l2 *ctx );

/* Various record header writing functions */
MBEDTLS_MPS_STATIC int l2_out_write_protected_record( mbedtls_mps_l2 *ctx,
                                                      mps_rec *rec );
#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l2_out_write_protected_record_tls( mbedtls_mps_l2 *ctx,
                                              mps_rec *rec );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l2_out_write_protected_record_dtls12( mbedtls_mps_l2 *ctx,
                                                 mps_rec *rec );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

MBEDTLS_MPS_STATIC int l2_out_release_and_dispatch( mbedtls_mps_l2 *ctx,
                                                    uint8_t force );
MBEDTLS_MPS_STATIC int l2_out_clear_pending( mbedtls_mps_l2 *ctx );

MBEDTLS_MPS_STATIC mbedtls_mps_size_t l2_get_header_len( mbedtls_mps_l2 *ctx,
                                                   mbedtls_mps_epoch_id epoch );

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_ALWAYS_INLINE
int l2_version_wire_matches_logical( uint8_t wire_version,
                                     int logical_version );
#endif /* MBEDTLS_MPS_PROTO_TLS */

/* Configuration related */
/* OPTIMIZATION: The flexibility of Layer 2 in terms of valid types,
 *               pausing, merging, and the acceptance of empty records
 *               is nice for testing, but on a low-profile production build
 *               targeted at a specific version of [D]TLS, code can be saved
 *               by implementing the l2_type_can_be_yyy() functions in a
 *               static way (comparing against a mask / list of types fixed
 *               at compile-time). */
#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l2_type_can_be_paused( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type );
#endif /* MBEDTLS_MPS_PROTO_TLS */
MBEDTLS_MPS_STATIC int l2_type_can_be_merged( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type );
MBEDTLS_MPS_STATIC int l2_type_is_valid( mbedtls_mps_l2 *ctx,
                             mbedtls_mps_msg_type_t type );
MBEDTLS_MPS_STATIC int l2_type_empty_allowed( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type );

/*
 * Epoch handling
 */

/* Print human-readable description of epoch usage flags. */
MBEDTLS_MPS_STATIC void l2_print_usage( unsigned usage );

#if defined(MBEDTLS_MPS_TRACE)
static inline const char * l2_epoch_usage_to_string(
    mbedtls_mps_epoch_usage usage )
{
    if( ( usage & MPS_EPOCH_READ_MASK  ) != 0 &&
        ( usage & MPS_EPOCH_WRITE_MASK ) != 0 )
    {
        return( "READ | WRITE" );
    }
    else if( ( usage & MPS_EPOCH_READ_MASK ) != 0 )
        return( "READ" );
    else if( ( usage & MPS_EPOCH_WRITE_MASK ) != 0 )
        return( "WRITE" );

    return( "NONE" );
}
#endif /* MBEDTLS_MPS_TRACE */

/* Internal macro used to indicate internal usage of an epoch,
 * e.g. because data it still pending to be dispatched.
 *
 * The `reason` parameter may range from 0 to 3.
 */
#define MPS_EPOCH_USAGE_INTERNAL( reason )  \
    ( (mbedtls_mps_epoch_usage) ( 1u << ( 4 + ( reason ) ) ) )

#define MPS_EPOCH_USAGE_INTERNAL_OUT_RECORD_OPEN \
    MPS_EPOCH_USAGE_INTERNAL( 0 )
#define MPS_EPOCH_USAGE_INTERNAL_OUT_PROTECTED  \
    MPS_EPOCH_USAGE_INTERNAL( 1 )

MBEDTLS_MPS_STATIC void l2_epoch_free( mbedtls_mps_l2_epoch_t *epoch );
MBEDTLS_MPS_STATIC void l2_epoch_init( mbedtls_mps_l2_epoch_t *epoch );

/* Check if an epoch can be used for a given purpose. */
MBEDTLS_MPS_STATIC int l2_epoch_check( mbedtls_mps_l2 *ctx,
                           mbedtls_mps_epoch_id epoch,
                           uint8_t purpose );

/* Lookup the transform associated to an epoch.
 *
 * The epoch ID is fully untrusted (this function is called
 * as part of replay protection for not yet authenticated
 * records).
 */
MBEDTLS_MPS_STATIC int l2_epoch_lookup( mbedtls_mps_l2 *ctx,
                            mbedtls_mps_epoch_id epoch_id,
                            mbedtls_mps_l2_epoch_t **epoch );

/* Check if some epochs are no longer needed and can be removed. */
MBEDTLS_MPS_STATIC int l2_epoch_cleanup( mbedtls_mps_l2 *ctx );

/*
 * Sequence number handling
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l2_tls_in_get_epoch_and_counter( mbedtls_mps_l2 *ctx,
                                                        uint16_t *dst_epoch,
                                                        uint32_t dst_ctr[2] );
#endif /* MBEDTLS_MPS_PROTO_TLS */

MBEDTLS_MPS_STATIC int l2_in_update_counter( mbedtls_mps_l2 *ctx,
                                             uint16_t epoch,
                                             uint32_t ctr_hi,
                                             uint32_t ctr_lo );

MBEDTLS_MPS_STATIC int l2_out_get_and_update_rec_seq( mbedtls_mps_l2 *ctx,
                                          mbedtls_mps_l2_epoch_t *epoch,
                                          uint32_t *dst_ctr );

MBEDTLS_MPS_STATIC int l2_increment_counter( uint32_t ctr[2] );

/*
 * DTLS replay protection
 */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
/* This function checks whether the record sequence number represented
 * by `ctr_lo` and `ctr_hi` is 'fresh' in the following sense:
 * - It hasn't been seen before.
 * - It's not too old.
 *
 * - Returns `0` if the sequence number is fresh.
 * - Returns `-1` otherwise.
 *
 * This function does not update the replay protection window.
 */
MBEDTLS_MPS_STATIC int l2_counter_replay_check( mbedtls_mps_l2 *ctx,
                                                mbedtls_mps_epoch_id epoch,
                                                uint32_t ctr_hi,
                                                uint32_t ctr_lo );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#endif /* MBEDTLS_MPS_RECORD_LAYER_INTERNAL_H */
