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
 * \file reader.h
 *
 * \brief This file defines reader objects, which together with their
 *        sibling writer objects form the basis for the communication
 *        between the various layers of the Mbed TLS messaging stack,
 *        as well as the communication between the messaging stack and
 *        the (D)TLS handshake protocol implementation.
 *
 * Readers provide a means of transferring incoming data from
 * a 'producer' providing it in chunks of arbitrary size, to
 * a 'consumer' which fetches and processes it in chunks of
 * again arbitrary, and potentially different, size.
 *
 * Readers can thus be seen as datagram-to-stream converters,
 * and they abstract away the following two tasks from the user:
 * 1. The pointer arithmetic of stepping through a producer-
 *    provided chunk in smaller chunks.
 * 2. The merging of incoming data chunks in case the
 *    consumer requests data in larger chunks than what the
 *    producer provides.
 *
 * The basic abstract flow of operation is the following:
 * - Initially, the reader is in 'producing mode'.
 * - The producer hands an incoming data buffer to the reader,
 *   moving it from 'producing' to 'consuming' mode.
 * - The consumer subsequently fetches and processes the buffer
 *   content. Once that's done -- or partially done and a consumer's
 *   request can't be fulfilled -- the producer revokes the reader's
 *   access to the incoming data buffer, putting the reader back to
 *   producing mode.
 * - The producer subsequently gathers more incoming data and hands
 *   it to the reader until it switches back to consuming mode
 *   if enough data is available for the last consumer request to
 *   be satisfiable.
 * - Repeat the above.
 *
 * The abstract states of the reader from the producer's and
 * consumer's perspective are as follows:
 *
 * - From the perspective of the consumer, the state of the
 *   reader consists of the following:
 *   - A byte stream representing (concatenation of) the data
 *     received through calls to mbedtls_mps_reader_get(),
 *   - A marker within that byte stream indicating which data
 *     can be considered processed, and hence need not be retained,
 *     when the reader is passed back to the producer via
 *     mbedtls_mps_reader_reclaim().
 *     The marker is set via mbedtls_mps_reader_commit()
 *     which places it at the end of the current byte stream.
 *   The consumer need not be aware of the distinction between consumer
 *   and producer mode, because it only interfaces with the reader
 *   when the latter is in consuming mode.
 *
 * - From the perspective of the producer, the reader's state is one of:
 *   - Attached: The reader is in consuming mode.
 *   - Unset: No incoming data buffer is currently managed by the reader,
 *            and all previously handed incoming data buffers have been
 *            fully processed. More data needs to be fed into the reader
 *            via mbedtls_mps_reader_feed().
 *
 *   - Accumulating: No incoming data buffer is currently managed by the
 *                   reader, but some data from the previous incoming data
 *                   buffer hasn't been processed yet and is internally
 *                   held back.
 *   The Attached state belongs to consuming mode, while the Unset and
 *   Accumulating states belong to producing mode.
 *
 * Transitioning from the Unset or Accumulating state to Attached is
 * done via successful calls to mbedtls_mps_reader_feed(), while
 * transitioning from Attached to either Unset or Accumulating (depending
 * on what has been processed) is done via mbedtls_mps_reader_reclaim().
 *
 * The following diagram depicts the producer-state progression:
 *
 *        +------------------+             reclaim
 *        |      Unset       +<-------------------------------------+       get
 *        +--------|---------+                                      |   +------+
 *                 |                                                |   |      |
 *                 |                                                |   |      |
 *                 |                feed                  +---------+---+--+   |
 *                 +-------------------------------------->                <---+
 *                                                        |    Attached    |
 *                 +-------------------------------------->                <---+
 *                 |     feed, enough data available      +---------+---+--+   |
 *                 |     to serve previous consumer request         |   |      |
 *                 |                                                |   |      |
 *        +--------+---------+                                      |   +------+
 *   +---->   Accumulating   |<-------------------------------------+    commit
 *   |    +---+--------------+      reclaim, previous read request
 *   |        |                        couldn't be fulfilled
 *   |        |
 *   +--------+
 *     feed, need more data to serve
 *     previous consumer request
 *                                         |
 *                                         |
 *               producing mode            |           consuming mode
 *                                         |
 *
 */

#ifndef MBEDTLS_MPS_READER_EXT_H
#define MBEDTLS_MPS_READER_EXT_H

#include <stdio.h>

#include "../library/mps_common.h"
#include "error.h"

#include "../library/mps_error.h"
#include "../library/mps_reader.h"

#define MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION      MBEDTLS_MPS_READER_MAKE_ERROR( 0x9 ) /*!< The attempted operation violates the bounds of the currently active group.    */
#define MBEDTLS_ERR_MPS_READER_TOO_MANY_GROUPS       MBEDTLS_MPS_READER_MAKE_ERROR( 0xa ) /*!< The extended reader has reached the maximum number of groups, and another
                                                        *   group cannot be opened.                                                       */


/*
 * Interface for extended reader
 */

struct mbedtls_mps_reader_ext;
typedef struct mbedtls_mps_reader_ext mbedtls_mps_reader_ext;

#define MBEDTLS_MPS_READER_MAX_GROUPS 4

struct mbedtls_mps_reader_ext
{
    unsigned cur_grp; /*!< The 0-based index of the currently active group.
                       *   The group of index 0 always exists and represents
                       *   the entire logical message buffer.                 */
    mbedtls_mps_stored_size_t grp_end[MBEDTLS_MPS_READER_MAX_GROUPS];
                      /*!< The offsets marking the ends of the currently
                       *   active groups. The first cur_grp + 1 entries are
                       *   valid and always weakly descending (subsequent
                       *   groups are subgroups of their predecessors ones).  */

    mbedtls_mps_reader *rd; /*!< Underlying writer object - may be \c NULL.       */
    mbedtls_mps_stored_size_t ofs_fetch;
                        /*!< The offset of the first byte of the next chunk.  */
    mbedtls_mps_stored_size_t ofs_commit;
                        /*!< The offset of first byte beyond
                         *   the last committed chunk.                        */
};

/**
 * \brief           Initialize an extended reader object
 *
 * \param reader    The extended reader context to initialize.
 * \param size      The total size of the logical buffer to
 *                  be managed by the extended reader.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_MPS_READER_XXX error code on failure.
 *
 */
int mbedtls_mps_reader_init_ext( mbedtls_mps_reader_ext *reader,
                             mbedtls_mps_size_t size );

/**
 * \brief           Free an extended reader object
 *
 * \param reader    The extended reader context to be freed.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_MPS_READER_XXX error code on failure.
 *
 */
int mbedtls_mps_reader_free_ext( mbedtls_mps_reader_ext *reader );

/**
 * \brief           Fetch a data chunk from an extended reader
 *
 * \param reader    The extended reader to be used.
 * \param desired   The desired amount of incoming data to be read.
 * \param buffer    The address at which to store the address
 *                  of the incoming data buffer on success.
 * \param buflen    The address at which to store the actual
 *                  size of the incoming data buffer on success.
 *                  May be \c NULL (see below).
 *
 * \return          \c 0 on success. In this case, \c *buf holds the
 *                  address of a buffer of size \c *buflen
 *                  (if \c buflen != NULL) or \p desired
 *                  (if \c buflen == \c NULL).
 * \return          #MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION if the read
 *                  request exceeds the bounds of the current group.
 * \return          Another negative \c MBEDTLS_ERR_MPS_READER_XXX error
 *                  for other kinds of failure.
 *
 * \note            Passing \c NULL as buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  It's functionally equivalent to passing a valid
 *                  address as buflen and checking \c *buflen == \c desired
 *                  afterwards.
 *
 *
 */
int mbedtls_mps_reader_get_ext( mbedtls_mps_reader_ext *reader,
                            mbedtls_mps_size_t desired,
                            unsigned char **buffer,
                            mbedtls_mps_size_t *buflen );

/**
 * \brief           Signal that all input buffers previously obtained
 *                  from mbedtls_mps_reader_get_ext are fully processed.
 * \param reader    The extended reader context to use.
 *
 *                  This function marks the previously fetched data as fully
 *                  processed and invalidates their respective buffers.
 *
 * \warning         Once this function is called, you must not use the
 *                  pointers corresponding to the committed data anymore.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_MPS_READER_XXX error code on failure.
 *
 */
int mbedtls_mps_reader_commit_ext( mbedtls_mps_reader_ext *reader );

/**
 * \brief            Open a new logical subbuffer.
 *
 * \param reader     The extended reader context to use.
 * \param group_size The offset of the end of the subbuffer
 *                   from the end of the last successful fetch.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION if
 *                  the new group is not contained in the
 *                  current group. In this case, the extended
 *                  reader is unchanged and hence remains intact.
 *                  This is a very important error condition that
 *                  catches e.g. if the length field for some
 *                  substructure (e.g. an extension within a Hello
 *                  message) claims that substructure to be larger
 *                  than the message itself.
 * \return          #MBEDTLS_ERR_MPS_READER_TOO_MANY_GROUPS if the internal
 *                  threshold for the maximum number of groups exceeded.
 *                  This is an internal error, and it should be
 *                  statically verifiable that it doesn't occur.
 * \return          Another negative \c MBEDTLS_ERR_MPS_READER_XXX error
 *                  for other kinds of failure.
 *
 */
int mbedtls_mps_reader_group_open( mbedtls_mps_reader_ext *reader,
                               mbedtls_mps_size_t group_size );

/**
 * \brief           Close the most recently opened logical subbuffer.
 *
 * \param reader    The extended reader context to use.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MPS_READER_BOUNDS_VIOLATION if
 *                  the current logical subbuffer hasn't been
 *                  fully fetched and committed.
 * \return          Another negative \c MBEDTLS_ERR_MPS_READER_XXX error
 *                  for other kinds of failure.
 *
 */
int mbedtls_mps_reader_group_close( mbedtls_mps_reader_ext *reader );

/**
 * \brief            Attach a reader to an extended reader.
 *
 *                   Once a reader has been attached to an extended reader,
 *                   subsequent calls to mbedtls_mps_reader_commit_ext and
 *                   mbedtls_mps_reader_get_ext will be routed through the
 *                   corresponding calls to mbedtls_mps_reader_commit resp.
 *                   mbedtls_mps_reader_get after the extended reader has
 *                   done its bounds checks.
 *
 * \param rd_ext     The extended reader context to use.
 * \param rd         The reader to bind to the extended reader \p rd_ext.
 *
 * \return           \c 0 on succes.
 * \return           Another negative error code on failure.
 *
 */
int mbedtls_mps_reader_attach( mbedtls_mps_reader_ext *rd_ext,
                           mbedtls_mps_reader *rd );

/**
 * \brief           Detach a reader from an extended reader.
 *
 * \param rd_ext    The extended reader context to use.
 *
 * \return          \c 0 on succes.
 * \return          Another negative error code on failure.
 *
 */
int mbedtls_mps_reader_detach( mbedtls_mps_reader_ext *rd_ext );

/**
 * \brief            Check if the extended reader is finished processing
 *                   the logical buffer it was setup with.
 *
 * \param rd_ext     The extended reader context to use.
 *
 * \return           \c 0 if all groups opened via mbedtls_mps_reader_group_open()
 *                   have been closed via mbedtls_mps_reader_group_close(), and
 *                   the entire logical buffer as defined by the \c size
 *                   argument in mbedtls_mps_reader_init_ext() has been fetched
 *                   and committed.
 * \return           A negative \c MBEDTLS_ERR_MPS_READER_XXX error code otherwise.
 *
 */
int mbedtls_mps_reader_check_done( mbedtls_mps_reader_ext const *rd_ext );

#endif /* MBEDTLS_MPS_READER_EXT_H */
