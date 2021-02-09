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

#ifndef MBEDTLS_MPS_BUFFER_LAYER_INTERNAL_H
#define MBEDTLS_MPS_BUFFER_LAYER_INTERNAL_H

#include "mbedtls/mps/layer1.h"

/*
 * Allocator related functions
 */

MBEDTLS_MPS_STATIC void l1_release_if_set( unsigned char **buf_ptr,
                               mps_alloc *ctx,
                               mps_alloc_type purpose );
MBEDTLS_MPS_STATIC int l1_acquire_if_unset( unsigned char **buf_ptr,
                                mbedtls_mps_size_t *buflen,
                                mps_alloc *ctx,
                                mps_alloc_type purpose );

/*
 * Functions related to stream-based implementation of Layer 1
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)

MBEDTLS_MPS_INLINE void l1_init_stream_read( mps_l1_stream_read *p,
                                        mps_alloc *ctx,
                                        void *recv_ctx,
                                        mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_init_stream_write( mps_l1_stream_write *p,
                                         mps_alloc *ctx,
                                         void *send_ctx,
                                         mps_l0_send_t *send );
MBEDTLS_MPS_INLINE void l1_init_stream( mps_l1_stream *p,
                                   mps_alloc *ctx,
                                   void *send_ctx,
                                   mps_l0_send_t *send,
                                   void *recv_ctx,
                                   mps_l0_recv_t *recv );

MBEDTLS_MPS_INLINE void l1_free_stream_read( mps_l1_stream_read *p );
MBEDTLS_MPS_INLINE void l1_free_stream_write( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE void l1_free_stream( mps_l1_stream *p );

MBEDTLS_MPS_INLINE void l1_set_bio_stream_read( mps_l1_stream_read *p,
                                                void *recv_ctx,
                                                mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_set_bio_stream_write( mps_l1_stream_write *p,
                                                 void *send_ctx,
                                                 mps_l0_send_t *send );
MBEDTLS_MPS_INLINE void l1_set_bio_stream( mps_l1_stream *p,
                                           void *send_ctx,
                                           mps_l0_send_t *send,
                                           void *recv_ctx,
                                           mps_l0_recv_t *recv );

MBEDTLS_MPS_INLINE int l1_fetch_stream( mps_l1_stream_read *p,
                                        unsigned char **dst,
                                        mbedtls_mps_size_t len );
MBEDTLS_MPS_INLINE int l1_write_stream( mps_l1_stream_write *p,
                                   unsigned char **dst,
                                   mbedtls_mps_size_t *buflen );

MBEDTLS_MPS_INLINE int l1_check_flush_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE int l1_flush_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE int l1_consume_stream( mps_l1_stream_read *p );
MBEDTLS_MPS_INLINE int l1_dispatch_stream( mps_l1_stream_write *p,
                                           mbedtls_mps_size_t len,
                                           mbedtls_mps_size_t *pending );

MBEDTLS_MPS_INLINE int l1_write_dependency_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE int l1_read_dependency_stream( mps_l1_stream_read *p );

#endif /* MBEDTLS_MPS_PROTO_TLS */

/*
 * Functions related to datagram-based implementation of Layer 1
 */

#if defined(MBEDTLS_MPS_PROTO_DTLS)

MBEDTLS_MPS_INLINE void l1_init_dgram_read( mps_l1_dgram_read *p,
                                       mps_alloc *ctx,
                                       void *recv_ctx,
                                       mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_init_dgram_write( mps_l1_dgram_write *p,
                                        mps_alloc *ctx,
                                        void *send_ctx,
                                        mps_l0_send_t *send );
MBEDTLS_MPS_INLINE void l1_init_dgram( mps_l1_dgram *p,
                                  mps_alloc *ctx,
                                  void *send_ctx,
                                  mps_l0_send_t *send,
                                  void *recv_ctx,
                                  mps_l0_recv_t *recv );

MBEDTLS_MPS_INLINE void l1_free_dgram_read( mps_l1_dgram_read *p );
MBEDTLS_MPS_INLINE void l1_free_dgram_write( mps_l1_dgram_write *p );
MBEDTLS_MPS_INLINE void l1_free_dgram( mps_l1_dgram *p );

MBEDTLS_MPS_INLINE void l1_set_bio_dgram_write( mps_l1_dgram_write *p,
                                                void *send_ctx,
                                                mps_l0_send_t *send );

MBEDTLS_MPS_INLINE void l1_set_bio_dgram_read( mps_l1_dgram_read *p,
                                               void *recv_ctx,
                                               mps_l0_recv_t *recv );

MBEDTLS_MPS_INLINE void l1_set_bio_dgram( mps_l1_dgram *p,
                                          void *send_ctx,
                                          mps_l0_send_t *send,
                                          void *recv_ctx,
                                          mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE int l1_fetch_dgram( mps_l1_dgram_read *p,
                                  unsigned char **dst,
                                  mbedtls_mps_size_t len );
MBEDTLS_MPS_INLINE int l1_consume_dgram( mps_l1_dgram_read *p );
MBEDTLS_MPS_INLINE int l1_write_dgram( mps_l1_dgram_write *p,
                                       unsigned char **buf,
                                       mbedtls_mps_size_t *buflen );
MBEDTLS_MPS_INLINE int l1_dispatch_dgram( mps_l1_dgram_write *p,
                                          mbedtls_mps_size_t len,
                                          mbedtls_mps_size_t *pending );

MBEDTLS_MPS_INLINE int l1_flush_dgram( mps_l1_dgram_write *p );
MBEDTLS_MPS_INLINE int l1_check_flush_dgram( mps_l1_dgram_write *p );

MBEDTLS_MPS_INLINE int l1_ensure_in_dgram( mps_l1_dgram_read *p );

MBEDTLS_MPS_INLINE int l1_write_dependency_dgram( mps_l1_dgram_write *p );
MBEDTLS_MPS_INLINE int l1_read_dependency_dgram( mps_l1_dgram_read *p );

#endif /* MBEDTLS_MPS_PROTO_DTLS */

#endif /* MBEDTLS_MPS_BUFFER_LAYER_INTERNAL */
