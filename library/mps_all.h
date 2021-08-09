/**
 * \file mps.h
 *
 * \brief Message Processing Stack
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_MPS_ALL_H
#define MBEDTLS_MPS_ALL_H

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_USE_MPS)

#include "mps_common.h"
#include "mps_allocator.h"
#include "mps_layer1.h"
#include "mps_layer2.h"
#include "mps_layer3.h"
#include "mps.h"

struct mbedtls_ssl_mps
{
    mps_alloc alloc;
    mps_l1 l1;
    mbedtls_mps_l2 l2;
    mps_l3 l3;
    mbedtls_mps l4;
};

#endif

#endif /* MBEDTLS_MPS_ALL_H */
