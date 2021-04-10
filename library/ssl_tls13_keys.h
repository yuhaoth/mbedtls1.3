/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
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
 */
#if !defined(MBEDTLS_SSL_TLS1_3_KEYS_H)
#define MBEDTLS_SSL_TLS1_3_KEYS_H

/* The maximum size of the intermediate key material.
 * The IKM can be a
 * - 0-string of length corresponding to the size of the
 *   underlying hash function, and hence can be bounded
 *   in size by MBEDTLS_MD_MAX_SIZE.
 * - the PSK, which is bounded in size by MBEDTLS_PREMASTER_SIZE
 * - the (EC)DHE, which is bounded in size by MBEDTLS_PREMASTER_SIZE
 */
#define MBEDTLS_SSL_TLS1_3_MAX_IKM_SIZE \
    ( MBEDTLS_PREMASTER_SIZE > MBEDTLS_MD_MAX_SIZE ? \
      MBEDTLS_PREMASTER_SIZE : MBEDTLS_MD_MAX_SIZE )

/* This requires MBEDTLS_SSL_TLS1_3_LABEL( idx, name, string ) to be defined at
 * the point of use. See e.g. the definition of mbedtls_ssl_tls1_3_labels_union
 * below. */
#define MBEDTLS_SSL_TLS1_3_LABEL_LIST                               \
    MBEDTLS_SSL_TLS1_3_LABEL( finished    , "finished"     ) \
    MBEDTLS_SSL_TLS1_3_LABEL( resumption  , "resumption"   ) \
    MBEDTLS_SSL_TLS1_3_LABEL( traffic_upd , "traffic upd"  ) \
    MBEDTLS_SSL_TLS1_3_LABEL( exporter    , "exporter"     ) \
    MBEDTLS_SSL_TLS1_3_LABEL( key         , "key"          ) \
    MBEDTLS_SSL_TLS1_3_LABEL( iv          , "iv"           ) \
    MBEDTLS_SSL_TLS1_3_LABEL( c_hs_traffic, "c hs traffic" ) \
    MBEDTLS_SSL_TLS1_3_LABEL( c_ap_traffic, "c ap traffic" ) \
    MBEDTLS_SSL_TLS1_3_LABEL( c_e_traffic , "c e traffic"  ) \
    MBEDTLS_SSL_TLS1_3_LABEL( s_hs_traffic, "s hs traffic" ) \
    MBEDTLS_SSL_TLS1_3_LABEL( s_ap_traffic, "s ap traffic" ) \
    MBEDTLS_SSL_TLS1_3_LABEL( s_e_traffic , "s e traffic"  ) \
    MBEDTLS_SSL_TLS1_3_LABEL( e_exp_master, "e exp master" ) \
    MBEDTLS_SSL_TLS1_3_LABEL( res_master  , "res master"   ) \
    MBEDTLS_SSL_TLS1_3_LABEL( exp_master  , "exp master"   ) \
    MBEDTLS_SSL_TLS1_3_LABEL( ext_binder  , "ext binder"   ) \
    MBEDTLS_SSL_TLS1_3_LABEL( res_binder  , "res binder"   ) \
    MBEDTLS_SSL_TLS1_3_LABEL( derived     , "derived"      )

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    const unsigned char name    [ sizeof(string) - 1 ];

union mbedtls_ssl_tls1_3_labels_union
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
struct mbedtls_ssl_tls1_3_labels_struct
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
#undef MBEDTLS_SSL_TLS1_3_LABEL

extern const struct mbedtls_ssl_tls1_3_labels_struct mbedtls_ssl_tls1_3_labels;

#define MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( LABEL )  \
    mbedtls_ssl_tls1_3_labels.LABEL,              \
    sizeof(mbedtls_ssl_tls1_3_labels.LABEL)

#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN  \
    sizeof( union mbedtls_ssl_tls1_3_labels_union )

/* The maximum length of HKDF contexts used in the TLS 1.3 standard.
 * Since contexts are always hashes of message transcripts, this can
 * be approximated from above by the maximum hash size. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN  \
    MBEDTLS_MD_MAX_SIZE

/* Maximum desired length for expanded key material generated
 * by HKDF-Expand-Label.
 *
 * Warning: If this ever needs to be increased, the implementation
 * ssl_tls1_3_hkdf_encode_label() in ssl_tls13_keys.c needs to be
 * adjusted since it currently assumes that HKDF key expansion
 * is never used with more than 255 Bytes of output. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN 255

/* Macro to express the length of the verify structure length.
 *
 * The structure is computed per TLS 1.3 specification as:
 *   - 64 bytes of octet 32,
 *   - 33 bytes for the context string
 *        (which is either "TLS 1.3, client CertificateVerify"
 *         or "TLS 1.3, server CertificateVerify"),
 *   - 1 byte for the octet 0x0, which servers as a separator,
 *   - 32 or 48 bytes for the Transcript-Hash(Handshake Context, Certificate)
 *     (depending on the size of the transcript_hash)
 */
#define MBEDTLS_SSL_VERIFY_STRUCT_MAX_SIZE  ( 64 +                 \
                                              33 +                 \
                                               1 +                 \
                                              MBEDTLS_MD_MAX_SIZE  \
                                            )

/**
 * \brief           The \c HKDF-Expand-Label function from
 *                  the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *                  HKDF-Expand-Label( Secret, Label, Context, Length ) =
 *                       HKDF-Expand( Secret, HkdfLabel, Length )
 * </tt>
 *
 * \param hash_alg  The identifier for the hash algorithm to use.
 * \param secret    The \c Secret argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p slen Bytes.
 * \param slen      The length of \p secret in Bytes.
 * \param label     The \c Label argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p llen Bytes.
 * \param llen      The length of \p label in Bytes.
 * \param ctx       The \c Context argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p clen Bytes.
 * \param clen      The length of \p context in Bytes.
 * \param buf       The destination buffer to hold the expanded secret.
 *                  This must be a writable buffer of length \p blen Bytes.
 * \param blen      The desired size of the expanded secret in Bytes.
 *
 * \returns         \c 0 on success.
 * \return          A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen );

/**
 * \brief           This function is part of the TLS 1.3 key schedule.
 *                  It extracts key and IV for the actual client/server traffic
 *                  from the client/server traffic secrets.
 *
 * From RFC 8446:
 *
 * <tt>
 *   [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
 *   [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)*
 * </tt>
 *
 * \param hash_alg      The identifier for the hash algorithm to be used
 *                      for the HKDF-based expansion of the secret.
 * \param client_secret The client traffic secret.
 *                      This must be a readable buffer of size \p slen Bytes
 * \param server_secret The server traffic secret.
 *                      This must be a readable buffer of size \p slen Bytes
 * \param slen          Length of the secrets \p client_secret and
 *                      \p server_secret in Bytes.
 * \param key_len       The desired length of the key to be extracted in Bytes.
 * \param iv_len        The desired length of the IV to be extracted in Bytes.
 * \param keys          The address of the structure holding the generated
 *                      keys and IVs.
 *
 * \returns             \c 0 on success.
 * \returns             A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys );


#define MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED 0
#define MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED   1

/**
 * \brief The \c Derive-Secret function from the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *   Derive-Secret( Secret, Label, Messages ) =
 *      HKDF-Expand-Label( Secret, Label,
 *                         Hash( Messages ),
 *                         Hash.Length ) )
 * </tt>
 *
 * \param hash_alg   The identifier for the hash function used for the
 *                   applications of HKDF.
 * \param secret     The \c Secret argument to the \c Derive-Secret function.
 *                   This must be a readable buffer of length \p slen Bytes.
 * \param slen       The length of \p secret in Bytes.
 * \param label      The \c Label argument to the \c Derive-Secret function.
 *                   This must be a readable buffer of length \p llen Bytes.
 * \param llen       The length of \p label in Bytes.
 * \param ctx        The hash of the \c Messages argument to the
 *                   \c Derive-Secret function, or the \c Messages argument
 *                   itself, depending on \p context_already_hashed.
 * \param clen       The length of \p hash.
 * \param ctx_hashed This indicates whether the \p ctx contains the hash of
 *                   the \c Messages argument in the application of the
 *                   \c Derive-Secret function
 *                   (value MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED), or whether
 *                   it is the content of \c Messages itself, in which case
 *                   the function takes care of the hashing
 *                   (value MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED).
 * \param dstbuf     The target buffer to write the output of
 *                   \c Derive-Secret to. This must be a writable buffer of
 *                   size \p buflen Bytes.
 * \param buflen     The length of \p dstbuf in Bytes.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t buflen );

/**
 * \brief Compute the next secret in the TLS 1.3 key schedule
 *
 * The TLS 1.3 key schedule proceeds as follows to compute
 * the three main secrets during the handshake: The early
 * secret for early data, the handshake secret for all
 * other encrypted handshake messages, and the master
 * secret for all application traffic.
 *
 * <tt>
 *                    0
 *                    |
 *                    v
 *     PSK ->  HKDF-Extract = Early Secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *  (EC)DHE -> HKDF-Extract = Handshake Secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *     0 -> HKDF-Extract = Master Secret
 * </tt>
 *
 * Each of the three secrets in turn is the basis for further
 * key derivations, such as the derivation of traffic keys and IVs;
 * see e.g. mbedtls_ssl_tls1_3_make_traffic_keys().
 *
 * This function implements one step in this evolution of secrets:
 *
 * <tt>
 *                old_secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *     input -> HKDF-Extract = new_secret
 * </tt>
 *
 * \param hash_alg    The identifier for the hash function used for the
 *                    applications of HKDF.
 * \param secret_old  The address of the buffer holding the old secret
 *                    on function entry. If not \c NULL, this must be a
 *                    readable buffer whose size matches the output size
 *                    of the hash function represented by \p hash_alg.
 *                    If \c NULL, an all \c 0 array will be used instead.
 * \param input       The address of the buffer holding the additional
 *                    input for the key derivation (e.g., the PSK or the
 *                    ephemeral (EC)DH secret). If not \c NULL, this must be
 *                    a readable buffer whose size \p input_len Bytes.
 *                    If \c NULL, an all \c 0 array will be used instead.
 * \param input_len   The length of \p input in Bytes. This must not be
 *                    larger than MBEDTLS_SSL_TLS1_3_MAX_IKM_SIZE.
 * \param secret_new  The address of the buffer holding the new secret
 *                    on function exit. This must be a writable buffer
 *                    whose size matches the output size of the hash
 *                    function represented by \p hash_alg.
 *                    This may be the same as \p secret_old.
 *
 * \returns           \c 0 on success.
 * \returns           A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new );

/* TODO: Document */
int mbedtls_ssl_generate_application_traffic_keys( mbedtls_ssl_context* ssl,
                                                   mbedtls_ssl_key_set* traffic_keys );
int mbedtls_ssl_generate_early_data_keys( mbedtls_ssl_context *ssl,
                                          mbedtls_ssl_key_set *traffic_keys );
int mbedtls_ssl_handshake_key_derivation( mbedtls_ssl_context* ssl,
                                          mbedtls_ssl_key_set* traffic_keys );
int mbedtls_ssl_generate_handshake_traffic_keys( mbedtls_ssl_context* ssl,
                                                 mbedtls_ssl_key_set* traffic_keys );
int mbedtls_ssl_generate_resumption_master_secret( mbedtls_ssl_context* ssl );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_create_binder( mbedtls_ssl_context *ssl,
                               int is_external,
                               unsigned char *psk, size_t psk_len,
                               const mbedtls_md_info_t *md,
                               const mbedtls_ssl_ciphersuite_t *suite_info,
                               unsigned char *result );
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

int mbedtls_ssl_tls1_3_derive_master_secret( mbedtls_ssl_context* ssl );

#endif /* MBEDTLS_SSL_TLS1_3_KEYS_H */
