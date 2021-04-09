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

#ifndef MBEDTLS_MPS_MESSAGE_EXTRACTION_LAYER_INTERNAL_H
#define MBEDTLS_MPS_MESSAGE_EXTRACTION_LAYER_INTERNAL_H

#include "mbedtls/mps/layer3.h"

/*
 * Handshake header parsing/writing
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l3_check_write_hs_hdr_tls( mps_l3 *l3 );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l3_check_write_hs_hdr_dtls( mps_l3 *l3 );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
MBEDTLS_MPS_STATIC int l3_check_write_hs_hdr( mps_l3 *l3 );

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l3_parse_hs_header_tls( mbedtls_mps_reader *rd,
                                               mps_l3_hs_in_internal *in );
MBEDTLS_MPS_STATIC int l3_write_hs_header_tls( mps_l3_hs_out_internal *hs );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l3_parse_hs_header_dtls( mbedtls_mps_reader *rd,
                                                mps_l3_hs_in_internal *in );
MBEDTLS_MPS_STATIC int l3_write_hs_header_dtls( mps_l3_hs_out_internal *hs );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

MBEDTLS_MPS_STATIC int l3_parse_hs_header( uint8_t mode, mbedtls_mps_reader *rd,
                               mps_l3_hs_in_internal *in );

/*
 * Other message types
 */

MBEDTLS_MPS_STATIC int l3_parse_alert( mbedtls_mps_reader *rd,
                           mps_l3_alert_in_internal *alert );
MBEDTLS_MPS_STATIC int l3_parse_ccs( mbedtls_mps_reader *rd );

/*
 * Miscellanious
 *
 * TODO: Document
 */

MBEDTLS_MPS_STATIC int l3_prepare_write( mps_l3 *l3,
                                         mbedtls_mps_msg_type_t type,
                                         mbedtls_mps_epoch_id epoch );
MBEDTLS_MPS_STATIC int l3_check_clear( mps_l3 *l3 );

#endif /* MBEDTLS_MPS_MESSAGE_EXTRACTION_LAYER_INTERNAL_H */
