/*
*  TLSv1.3 server-side functions
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

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#if defined(MBEDTLS_SSL_SRV_C)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "ssl_misc.h"
#include "ssl_tls13_keys.h"

#include <string.h>

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
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


#endif /* MBEDTLS_SSL_SRV_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
