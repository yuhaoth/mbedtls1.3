/*
 *  Message Processing Stack, Reader implementation
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
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/mps/reader.h"
#include "mbedtls/mps/common.h"
#include "mbedtls/mps/trace.h"

#include <string.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if defined(MBEDTLS_MPS_ENABLE_TRACE)
static int mbedtls_mps_trace_id = MBEDTLS_MPS_TRACE_BIT_READER;
#endif /* MBEDTLS_MPS_ENABLE_TRACE */

/*
 * Implementation of extended reader
 */

/* TODO: Consider making (some of) these functions inline. */

int mbedtls_mps_reader_init_ext( mbedtls_mps_reader_ext *rd_ext,
                             mbedtls_mps_size_t size )
{
    mbedtls_mps_reader_ext zero = { 0, { 0 }, NULL, 0, 0, };
    MBEDTLS_MPS_TRACE_INIT( "reader_init_ext, size %u", (unsigned) size );

    *rd_ext = zero;
    rd_ext->grp_end[0] = size;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_free_ext( mbedtls_mps_reader_ext *rd )
{
    mbedtls_mps_reader_ext zero = { 0, { 0 }, NULL, 0, 0, };
    MBEDTLS_MPS_TRACE_INIT( "reader_free_ext" );
    *rd = zero;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_get_ext( mbedtls_mps_reader_ext *rd_ext,
                            mbedtls_mps_size_t desired,
                            unsigned char **buffer,
                            mbedtls_mps_size_t *buflen )
{
    int ret;
    mbedtls_mps_size_t logic_avail;
    MBEDTLS_MPS_TRACE_INIT( "reader_get_ext %p: desired %u", (void*) rd_ext, (unsigned) desired );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( rd_ext->rd != NULL,
                "mbedtls_mps_reader_get_ext() without underlying reader" );

    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT, "* Fetch offset: %u", (unsigned) rd_ext->ofs_fetch );
    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT, "* Group end:    %u",
           (unsigned) rd_ext->grp_end[rd_ext->cur_grp] );
    logic_avail = rd_ext->grp_end[rd_ext->cur_grp] - rd_ext->ofs_fetch;
    if( desired > logic_avail )
    {
        MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT, "Requesting more data (%u) than logically available (%u)",
               (unsigned) desired, (unsigned) logic_avail );
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION );
    }

    ret = mbedtls_mps_reader_get( rd_ext->rd, desired, buffer, buflen );
    if( ret != 0 )
        MBEDTLS_MPS_TRACE_RETURN( ret );

    if( buflen != NULL )
        desired = *buflen;

    rd_ext->ofs_fetch += desired;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_commit_ext( mbedtls_mps_reader_ext *rd_ext )
{
    int ret;
    MBEDTLS_MPS_TRACE_INIT( "reader_commit_ext" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( rd_ext->rd != NULL,
          "mbedtls_mps_reader_commit_ext() without underlying reader" );

    ret = mbedtls_mps_reader_commit( rd_ext->rd );
    if( ret != 0 )
        MBEDTLS_MPS_TRACE_RETURN( ret );

    rd_ext->ofs_commit = rd_ext->ofs_fetch;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_group_open( mbedtls_mps_reader_ext *rd_ext,
                               mbedtls_mps_size_t group_size )
{
    /* Check how much space is left in the current group */
    mbedtls_mps_size_t const logic_avail =
        rd_ext->grp_end[rd_ext->cur_grp] - rd_ext->ofs_fetch;
    MBEDTLS_MPS_TRACE_INIT( "reader_group_open, size %u", (unsigned) group_size );

    if( rd_ext->cur_grp >= MBEDTLS_MPS_READER_MAX_GROUPS - 1 )
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_READER_TOO_MANY_GROUPS );

    /* Make sure the new group doesn't exceed the present one */
    if( logic_avail < group_size )
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION );

    /* Add new group */
    rd_ext->cur_grp++;
    rd_ext->grp_end[rd_ext->cur_grp] = rd_ext->ofs_fetch + group_size;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_group_close( mbedtls_mps_reader_ext *rd_ext )
{
    /* Check how much space is left in the current group */
    mbedtls_mps_size_t const logic_avail =
        rd_ext->grp_end[rd_ext->cur_grp] - rd_ext->ofs_fetch;
    MBEDTLS_MPS_TRACE_INIT( "reader_group_close" );

    /* Ensure that the group is fully exhausted */
    if( logic_avail != 0 )
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION );

    if( rd_ext->cur_grp > 0 )
        rd_ext->cur_grp--;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_attach( mbedtls_mps_reader_ext *rd_ext,
                           mbedtls_mps_reader *rd )
{
    MBEDTLS_MPS_TRACE_INIT( "reader_attach" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( rd_ext->rd == NULL,
       "mbedtls_mps_reader_attach() called with already attached ext. reader" );

    rd_ext->rd = rd;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_detach( mbedtls_mps_reader_ext *rd_ext )
{
    MBEDTLS_MPS_TRACE_INIT( "reader_detach" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( rd_ext->rd != NULL,
       "mbedtls_mps_reader_attach() called with already detached ext. reader" );

    rd_ext->ofs_fetch = rd_ext->ofs_commit;
    rd_ext->rd = NULL;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_reader_check_done( mbedtls_mps_reader_ext const *rd_ext )
{
    MBEDTLS_MPS_TRACE_INIT( "reader_check_done" );
    if( rd_ext->cur_grp > 0 ||
        rd_ext->ofs_commit != rd_ext->grp_end[0] )
    {
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION );
    }

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
