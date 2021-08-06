/**
 * \file ecp_internal.h
 *
 * \brief ECC-related functions with external linkage but which are
 *        not part of the public API.
 */
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
 */
#ifndef MBEDTLS_ECP_INTERNAL_H
#define MBEDTLS_ECP_INTERNAL_H

#include "common.h"
#include "mbedtls/ecp.h"

/* Convert NamedCurve (RFC 4492) to an Mbed TLS internal curve id.
 * - Returns MBEDTLS_ERR_ECP_BAD_INPUT_DATA if buffer is too small.
 * - Returns MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE is the group is unknown. */
int mbedtls_ecp_tls_read_named_curve( mbedtls_ecp_group_id *grp,
                                      const unsigned char *buf,
                                      size_t len );

#endif /* MBEDTLS_ECP_INTERNAL_H */
