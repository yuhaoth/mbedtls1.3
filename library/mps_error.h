/*
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/**
 * \file mps_error.h
 *
 * \brief Error codes used by MPS
 */

#ifndef MBEDTLS_MPS_ERROR_H
#define MBEDTLS_MPS_ERROR_H


/* TODO: The error code allocation needs to be revisited:
 *
 * - Should we make (some of) the MPS Reader error codes public?
 *   If so, we need to adjust MBEDTLS_MPS_READER_MAKE_ERROR() to hit
 *   a gap in the Mbed TLS public error space.
 *   If not, we have to make sure we don't forward those errors
 *   at the level of the public API -- no risk at the moment as
 *   long as MPS is an experimental component not accessible from
 *   public API.
 */

/**
 * MPS-specific error codes
 */

/*
 * Error codes visible at the MPS boundary.
 */

/*! A request for dynamic memory allocation failed. */
#define MBEDTLS_ERR_MPS_OUT_OF_MEMORY         MBEDTLS_MPS_MAKE_ERROR( 0x01 )
/*! The requested operation is not supported. */
#define MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED MBEDTLS_MPS_MAKE_ERROR( 0x02 )
/*! The requested operation cannot be performed in the current state. */
//#define MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED  MBEDTLS_MPS_MAKE_ERROR( 0x03 )
/*! The peer has sent a closure notification alert. */
#define MBEDTLS_ERR_MPS_CLOSE_NOTIFY          MBEDTLS_MPS_MAKE_ERROR( 0x04 )
/*! The MPS is blocked. */
#define MBEDTLS_ERR_MPS_BLOCKED               MBEDTLS_MPS_MAKE_ERROR( 0x05 )
/*! The peer has sent a fatal alert. */
#define MBEDTLS_ERR_MPS_FATAL_ALERT_RECEIVED  MBEDTLS_MPS_MAKE_ERROR( 0x07 )
/*! An internal assertion has failed - should never happen. */
//#define MBEDTLS_ERR_MPS_INTERNAL_ERROR        MBEDTLS_MPS_MAKE_ERROR( 0x08 )
#define MBEDTLS_ERR_MPS_RETRY                 MBEDTLS_MPS_MAKE_ERROR( 0x09 )
#define MBEDTLS_ERR_MPS_COUNTER_WRAP          MBEDTLS_MPS_MAKE_ERROR( 0x0a )
#define MBEDTLS_ERR_MPS_FLIGHT_TOO_LONG       MBEDTLS_MPS_MAKE_ERROR( 0x0b )

/*! MPS cannot handle the amount of record fragmentation used by the peer.
 *  This happens e.g. if fragmented handshake records are interleaved with
 *  fragmented alert records. */
#define MBEDTLS_ERR_MPS_EXCESS_RECORD_FRAGMENTATION  MBEDTLS_MPS_MAKE_ERROR( 0x0c )
/*! Layer 2 has been asked to pause a non-pausable record type. */
#define MBEDTLS_ERR_MPS_INVALID_RECORD_FRAGMENTATION MBEDTLS_MPS_MAKE_ERROR( 0x0d )
/*! The epoch under consideration exceeds the current epoch window. */
#define MBEDTLS_ERR_MPS_TOO_MANY_LIVE_EPOCHS  MBEDTLS_MPS_MAKE_ERROR( 0x0e )
#define MBEDTLS_ERR_MPS_TOO_MANY_EPOCHS       MBEDTLS_MPS_MAKE_ERROR( 0x0f )
/*! The underlying transport does not have enough incoming data available
 *  to perform the requested read operation. */
#define MBEDTLS_ERR_MPS_WANT_READ             MBEDTLS_MPS_MAKE_ERROR( 0x10 )
/*! The underlying transport has been closed. */
#define MBEDTLS_ERR_MPS_CONN_EOF              MBEDTLS_MPS_MAKE_ERROR( 0x70 )
/*! The underlying transport is unavailable perform the send operation. */
#define MBEDTLS_ERR_MPS_WANT_WRITE            MBEDTLS_MPS_MAKE_ERROR( 0x11 )
#define MBEDTLS_ERR_MPS_BAD_TRANSFORM         MBEDTLS_MPS_MAKE_ERROR( 0x12 )
/*! An internal buffer was too small for a necessary operation.
 *  This is at the moment returned in the following situations:
 *  - The read-buffer handed out by the allocator is not large enough
 *    to hold an incoming TLS record. The user should revise either
 *    + the configuration of the allocator, or
 *    + the configuration of the maximum record length.
 *      TODO: This max record length configuration still needs to be written.
 *  - The user requested more data from the reader handed out by MPS
 *    than what was passed to as `max_read` to mbedtls_mps_init().
 *    TODO: Add this to mbedtls_mps_init() and mbedtls_mps_l3_init(), and
 *          forward it to mbedtls_mps_l2_init() accordingly, where the
 *          `max_read` and `max_write` parameters are already present.
 */
#define MBEDTLS_ERR_MPS_BUFFER_TOO_SMALL      MBEDTLS_MPS_MAKE_ERROR( 0x13 )
/*! A request was made to send non-handshake data while an
 *  an outgoing handshake message was paused. */
#define MBEDTLS_ERR_MPS_NO_INTERLEAVING       MBEDTLS_MPS_MAKE_ERROR( 0x14 )
/*! A request was made to prematurely end the reading/writing
 *  of a handshake message. For reading, this means that strictly
 *  less data was read and committed from the handshake reader than
 *  what was specified in the handshake message header. For writing,
 *  this means that strictly less data was written and committed to the
 *  handshake writer than what was specified as the total handshake
 *  length when calling mbedtls_mps_write_handshake(). */
#define MBEDTLS_ERR_MPS_UNFINISHED_HS_MSG     MBEDTLS_MPS_MAKE_ERROR( 0x15 )
/*! The allocator used by MPS couldn't serve an allocation request. */
#define MBEDTLS_ERR_MPS_ALLOC_OUT_OF_SPACE    MBEDTLS_MPS_MAKE_ERROR( 0x16 )
/*! The parameter validation failed. */
#define MBEDTLS_ERR_MPS_INVALID_ARGS          MBEDTLS_MPS_MAKE_ERROR( 0x17 )
/*! The user passed an invalid epoch to
 *  mbedtls_mps_set_incoming_keys() or
 *  mbedtls_mps_set_outgoing_keys(). */
#define MBEDTLS_ERR_MPS_INVALID_EPOCH         MBEDTLS_MPS_MAKE_ERROR( 0x18 )
/*! The record header is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_CONTENT       MBEDTLS_MPS_MAKE_ERROR( 0x19 )
/*! The record header is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_RECORD        MBEDTLS_MPS_MAKE_ERROR( 0x1a )
/*! The record MAC is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_MAC           MBEDTLS_MPS_MAKE_ERROR( 0x1b )
#define MBEDTLS_ERR_MPS_BAD_TRANSPORT         MBEDTLS_MPS_MAKE_ERROR( 0x21 )

/*
 * Internal error codes
 */

#define MBEDTLS_ERR_MPS_NO_FORWARD                       MBEDTLS_MPS_MAKE_ERROR( 0x0c )
#define MBEDTLS_ERR_MPS_FLIGHT_RETRANSMISSION            MBEDTLS_MPS_MAKE_ERROR( 0x1c )
#define MBEDTLS_ERR_MPS_REPLAYED_RECORD                  MBEDTLS_MPS_MAKE_ERROR( 0x1d )
#define MBEDTLS_ERR_MPS_REQUEST_OUT_OF_BOUNDS            MBEDTLS_MPS_MAKE_ERROR( 0x1e )
#define MBEDTLS_ERR_MPS_RETRANSMISSION_HANDLE_UNFINISHED MBEDTLS_MPS_MAKE_ERROR( 0x1f )
#define MBEDTLS_ERR_MPS_REASSEMBLY_FEED_NEED_MORE        MBEDTLS_MPS_MAKE_ERROR( 0x20 )

/*
 * Helper macro to traverse MPS error codes
 *
 * This macro unfolds to the concatenation of applications of
 * ```
 *    MBEDTLS_MPS_ERROR_INFO( string, code, flags )
 * ```
 * where there is one application per error-code, and the
 * macro is being passed
 * - the string representation of the error, e.g.
 *   "MBEDTLS_ERR_MPS_INVALID_RECORD"
 * - the numeric error code
 * - error flags indicating whether the error code is
 *   externally visible, fatal, TLS only, ...
 *
 * See the generic failure handler in mps.c for an example of
 * how to use this macro.
 */

#define MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ( 1u << 0 )
#define MBEDTLS_MPS_ERROR_FLAGS_FATAL    ( 1u << 1 )
#define MBEDTLS_MPS_ERROR_FLAGS_TLS_ONLY ( 1u << 2 )

#define MBEDTLS_MPS_ERROR_IS_FATAL( flags )              \
    ( ( flags & MBEDTLS_MPS_ERROR_FLAGS_FATAL ) != 0 )
#define MBEDTLS_MPS_ERROR_IS_TLS_ONLY( flags )           \
    ( ( flags & MBEDTLS_MPS_ERROR_FLAGS_TLS_ONLY ) != 0 )
#define MBEDTLS_MPS_ERROR_IS_EXTERNAL( flags )           \
    ( ( flags & MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ) != 0 )

#define MBEDTLS_MPS_MAKE_ERROR_INFO( flags, name )      \
    #name, name, flags

#define EXPAND(x) x
#define MBEDTLS_MPS_ERROR_INFO_WRAP( x ) EXPAND(MBEDTLS_MPS_ERROR_INFO(x))

#define MBEDTLS_ERR_MPS_ERROR_LIST                                      \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                             \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_OUT_OF_MEMORY ) )                           \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED ) )                   \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED ) )                    \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ),                       \
            MBEDTLS_ERR_MPS_CLOSE_NOTIFY ) )                            \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ),                       \
            MBEDTLS_ERR_MPS_BLOCKED ) )                                 \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_FATAL_ALERT_RECEIVED ) )                    \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_INTERNAL_ERROR ) )                          \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL  ),                      \
            MBEDTLS_ERR_MPS_RETRY ) )                                   \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_NO_FORWARD ) )                              \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_COUNTER_WRAP ) )                            \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_FLIGHT_TOO_LONG ) )                         \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_EXCESS_RECORD_FRAGMENTATION ) )             \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_INVALID_RECORD_FRAGMENTATION ) )            \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_TOO_MANY_LIVE_EPOCHS ) )                    \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_TOO_MANY_EPOCHS ) )                         \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ),                       \
            MBEDTLS_ERR_MPS_CONN_EOF ) )                                \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ),                       \
            MBEDTLS_ERR_MPS_WANT_READ ) )                               \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL  ),                      \
            MBEDTLS_ERR_MPS_WANT_WRITE ) )                              \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL ),                       \
            MBEDTLS_ERR_SSL_WANT_READ ) )                               \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL  ),                      \
            MBEDTLS_ERR_SSL_WANT_WRITE ) )                              \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_BAD_TRANSFORM ) )                           \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_BUFFER_TOO_SMALL ) )                        \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_NO_INTERLEAVING ) )                         \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_UNFINISHED_HS_MSG ) )                       \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_ALLOC_OUT_OF_SPACE ) )                      \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_INVALID_ARGS ) )                            \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_INVALID_EPOCH ) )                           \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_INVALID_CONTENT ) )                         \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL    |                        \
              MBEDTLS_MPS_ERROR_FLAGS_TLS_ONLY ),                       \
            MBEDTLS_ERR_MPS_INVALID_RECORD ) )                          \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_EXTERNAL |                        \
              MBEDTLS_MPS_ERROR_FLAGS_FATAL    |                        \
              MBEDTLS_MPS_ERROR_FLAGS_TLS_ONLY ),                       \
            MBEDTLS_ERR_MPS_INVALID_MAC ) )                             \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_BAD_TRANSPORT ) )                           \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_FLIGHT_RETRANSMISSION ) )                   \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_REPLAYED_RECORD ) )                         \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_REQUEST_OUT_OF_BOUNDS ) )                   \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_RETRANSMISSION_HANDLE_UNFINISHED ) )        \
    MBEDTLS_MPS_ERROR_INFO_WRAP(                                        \
        MBEDTLS_MPS_MAKE_ERROR_INFO(                                    \
            ( MBEDTLS_MPS_ERROR_FLAGS_FATAL ),                          \
            MBEDTLS_ERR_MPS_REASSEMBLY_FEED_NEED_MORE ) )


/**
 * \name SECTION:       MPS general error codes
 *
 * \{
 */

#ifndef MBEDTLS_MPS_ERR_BASE
#define MBEDTLS_MPS_ERR_BASE ( 0 )
#endif

#define MBEDTLS_MPS_MAKE_ERROR(code) \
    ( -( MBEDTLS_MPS_ERR_BASE | (code) ) )

#define MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED  MBEDTLS_MPS_MAKE_ERROR( 0x1 )
#define MBEDTLS_ERR_MPS_INTERNAL_ERROR        MBEDTLS_MPS_MAKE_ERROR( 0x2 )

/* \} name SECTION: MPS general error codes */

/**
 * \name SECTION:       MPS Reader error codes
 *
 * \{
 */

#ifndef MBEDTLS_MPS_READER_ERR_BASE
#define MBEDTLS_MPS_READER_ERR_BASE ( 1 << 8 )
#endif

#define MBEDTLS_MPS_READER_MAKE_ERROR(code) \
    ( -( MBEDTLS_MPS_READER_ERR_BASE | (code) ) )

/*! An attempt to reclaim the data buffer from a reader failed because
 *  the user hasn't yet read and committed all of it. */
#define MBEDTLS_ERR_MPS_READER_DATA_LEFT             MBEDTLS_MPS_READER_MAKE_ERROR( 0x1 )

/*! An invalid argument was passed to the reader. */
#define MBEDTLS_ERR_MPS_READER_INVALID_ARG           MBEDTLS_MPS_READER_MAKE_ERROR( 0x2 )

/*! An attempt to move a reader to consuming mode through mbedtls_mps_reader_feed()
 *  after pausing failed because the provided data is not sufficient to serve the
 *  read requests that led to the pausing. */
#define MBEDTLS_ERR_MPS_READER_NEED_MORE             MBEDTLS_MPS_READER_MAKE_ERROR( 0x3 )

/*! A get request failed because not enough data is available in the reader. */
#define MBEDTLS_ERR_MPS_READER_OUT_OF_DATA           MBEDTLS_MPS_READER_MAKE_ERROR( 0x4 )

/*!< A get request after pausing and reactivating the reader failed because
 *   the request is not in line with the request made prior to pausing. The user
 *   must not change it's 'strategy' after pausing and reactivating a reader. */
#define MBEDTLS_ERR_MPS_READER_INCONSISTENT_REQUESTS MBEDTLS_MPS_READER_MAKE_ERROR( 0x5 )

/*! An attempt to reclaim the data buffer from a reader failed because the reader
 *  has no accumulator it can use to backup the data that hasn't been processed. */
#define MBEDTLS_ERR_MPS_READER_NEED_ACCUMULATOR      MBEDTLS_MPS_READER_MAKE_ERROR( 0x6 )

/*! An attempt to reclaim the data buffer from a reader failed because the
 *  accumulator passed to the reader is not large enough to hold both the
 *  data that hasn't been processed and the excess of the last read-request. */
#define MBEDTLS_ERR_MPS_READER_ACCUMULATOR_TOO_SMALL MBEDTLS_MPS_READER_MAKE_ERROR( 0x7 )

#define MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION      MBEDTLS_MPS_READER_MAKE_ERROR( 0x9 ) /*!< The attempted operation violates the bounds of the currently active group.    */
#define MBEDTLS_ERR_MPS_READER_TOO_MANY_GROUPS       MBEDTLS_MPS_READER_MAKE_ERROR( 0xa ) /*!< The extended reader has reached the maximum number of groups, and another
                                                        *   group cannot be opened.                                                       */

/* \} name SECTION: MPS Reader error codes */

/*
 * Error codes returned from the writer.
 */

/** An attempt was made to reclaim a buffer from the writer,
 *  but the buffer hasn't been fully used up, yet.            */
#define MBEDTLS_ERR_WRITER_DATA_LEFT             MBEDTLS_WRITER_MAKE_ERROR( 0x1 )
/** The validation of input parameters failed.                */
#define MBEDTLS_ERR_WRITER_INVALID_ARG           MBEDTLS_WRITER_MAKE_ERROR( 0x2 )
/** The provided outgoing data buffer was not large enough to
 *  hold all queued data that's currently pending to be
 *  delivered.                                                */
#define MBEDTLS_ERR_WRITER_NEED_MORE             MBEDTLS_WRITER_MAKE_ERROR( 0x3 )
/** The requested operation is not possible
 *  in the current state of the writer.                       */
#define MBEDTLS_ERR_WRITER_OPERATION_UNEXPECTED  MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED
/** The remaining amount of space for outgoing data is not
 *  sufficient to serve the user's request. The current
 *  outgoing data buffer must be reclaimed, dispatched,
 *  and a fresh outgoing data buffer must be fed to the
 *  writer.                                                   */
#define MBEDTLS_ERR_WRITER_OUT_OF_DATA           MBEDTLS_WRITER_MAKE_ERROR( 0x5 )
/** A write-request was issued to the extended writer that
 *  exceeds the bounds of the most recently added group.      */
#define MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION      MBEDTLS_WRITER_MAKE_ERROR( 0x9 )
/** The extended writer has reached the maximum number of
 *  groups, and another group cannot be added.                */
#define MBEDTLS_ERR_WRITER_TOO_MANY_GROUPS       MBEDTLS_WRITER_MAKE_ERROR( 0xa )

/** The identifier to use in mbedtls_writer_reclaim() to
 *  force the reclamation of the outgoing data buffer even
 *  if there's space remaining.                               */
#define MBEDTLS_WRITER_RECLAIM_FORCE 1
/** The identifier to use in mbedtls_writer_reclaim() if
 *  the call should only succeed if the current outgoing data
 *  buffer has been fully used up.                            */
#define MBEDTLS_WRITER_RECLAIM_NO_FORCE 0


#endif /* MBEDTLS_MPS_ERROR_H */
