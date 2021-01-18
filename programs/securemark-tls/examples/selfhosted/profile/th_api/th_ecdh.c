/*
 * Copyright (C) EEMBC(R). All Rights Reserved
 * 
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.  
 * 
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#if defined(CRYPTO_MBEDTLS)
#include "mbedtls/config.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h" 
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
#include "mbedtls/config.h"
#include "psa/crypto.h"

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_ECP_C) || !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#error "Necessary PSA functionality not defined!"
#endif


struct psa_ke_structure
{
    psa_key_attributes_t *client_attributes;  // own key attributes
    psa_key_handle_t client_key_handle;       // own key handle
    unsigned char *p_public;                  // public key of peer
    unsigned int publen;                      // peer public key length
};

typedef struct psa_ke_structure psa_ke_structure;
#endif /* CRYPTO_PSA */

#include "ee_ecdh.h"

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_create(
    void **p_context // output: portable context
)
{
#if defined(CRYPTO_MBEDTLS)
    mbedtls_ecdh_context *p_ecdh;

    p_ecdh = (mbedtls_ecdh_context *)th_malloc(sizeof(mbedtls_ecdh_context)); 
    if (p_ecdh == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }

    *p_context = (void *)p_ecdh;
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_ke_structure *context;

    context = 
       (psa_ke_structure *)th_malloc(sizeof(psa_ke_structure));
    if (context == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }
    memset(context,0,sizeof(psa_ke_structure));

    context->client_attributes = th_malloc(sizeof(psa_key_attributes_t));
    memset(context->client_attributes, 0, sizeof(psa_key_attributes_t));

    *p_context = context;
#endif /* CRYPTO_PSA */
    return EE_STATUS_OK;
}

#if defined(CRYPTO_MBEDTLS)

/**
 * Load a 64-byte public key from a peer, big-endian; confim is on curve
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
load_public_peer_key(
    void          *p_context,
    unsigned char *p_pub,
    size_t         publen
)
{
    mbedtls_ecdh_context *p_ecdh;
    mbedtls_ecp_point     Q;
    unsigned char         uncompressed_point_buffer[65];
    int                   ret;

    p_ecdh = (mbedtls_ecdh_context *)p_context;

    mbedtls_ecp_point_init(&Q);

    // First byte for mbedtls_ecp_point_read_binary must be 0x04
    uncompressed_point_buffer[0] = 0x04;
    th_memcpy(&(uncompressed_point_buffer[1]), p_pub, publen);

    ret = mbedtls_ecp_point_read_binary(
        &p_ecdh->grp,
        &Q,
        uncompressed_point_buffer,
        65
    );
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_point_read_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecp_check_pubkey(&p_ecdh->grp, &Q);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_check_pubkey: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecp_copy(&p_ecdh->Qp, &Q); 
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_copy: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Load private & populate ecdh->Q public point
 */
ee_status_t
load_private_key(
    void          *p_context,
    unsigned char *p_private,
    size_t         prilen
) {
    int                   ret;
    mbedtls_ecdh_context *p_ecdh;
    mbedtls_ecp_group    *p_grp;

    p_ecdh = (mbedtls_ecdh_context *)p_context;
    p_grp = &p_ecdh->grp;

    ret = mbedtls_mpi_read_binary(&p_ecdh->d, p_private, prilen);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_mpi_read_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    // compute the public key from the provided secret
    mbedtls_ecp_point_init(&p_ecdh->Q);
    ret = mbedtls_ecp_mul(
        p_grp,
        &p_ecdh->Q, // R <-- this value will be computed as P * m
        &p_ecdh->d, // m
        &p_grp->G,  // P
        NULL,
        0
    );
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_mul: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}
#endif /* CRYPTO_MBEDTLS */

/**
 * Initialize to a group (must be in the EE_ enum)
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_init(
    void           *p_context, // input: portable context
    ecdh_group_t    group,     // input: see `ecdh_group_t` for options
    unsigned char  *p_private, // input: private key, from host
    unsigned int    prilen,    // input: private key length in bytes
    unsigned char  *p_public,  // input: peer public key, from host
    unsigned int    publen     // input: peer public key length in bytes
)
{
#if defined(CRYPTO_MBEDTLS)
    int                   ret;

    mbedtls_ecdh_context *p_ecdh;
    
    p_ecdh = (mbedtls_ecdh_context *)p_context;
    switch (group)
    { 
        case EE_P256R1:
            mbedtls_ecdh_init(p_ecdh);
            ret = mbedtls_ecp_group_load(&p_ecdh->grp, MBEDTLS_ECP_DP_SECP256R1);
            if (ret)
            {
                th_printf("e-[mbedtls_ecp_group_load: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
            break; 
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }

    ret = load_public_peer_key(p_context, p_public, publen);
    if (ret != EE_STATUS_OK)
    {
        th_printf("e-[load_public_peer_key: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = load_private_key(p_context, p_private, prilen);
    if (ret != EE_STATUS_OK)
    {
        th_printf("e-[load_private_key: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_ke_structure *context = (psa_ke_structure *) p_context;
    psa_status_t status;

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_crypto_init: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    switch (group)
    { 
        case EE_P256R1:
            psa_set_key_usage_flags( context->client_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( context->client_attributes, PSA_ALG_ECDH );
            psa_set_key_type( context->client_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );

            break; 
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }

    // Copy public key of peer into internal context structure
    context->p_public = th_malloc(publen);
    if (context->p_public == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_init\r\n");
        return EE_STATUS_ERROR;
    }
    memcpy(context->p_public, p_public, publen);
    context->publen = publen;

    // Import own private key
    status = psa_import_key(context->client_attributes, p_private, prilen, &context->client_key_handle );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_import_key (client): -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_PSA */

    return EE_STATUS_OK;
}

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_calc_secret(
    void          *p_context,  // input: portable context
    unsigned char *p_secret,   // output: shared secret
    unsigned int   slen        // input: length of shared buffer in bytes
)
{
    size_t                olen;
#if defined(CRYPTO_MBEDTLS)
    mbedtls_ecdh_context *p_ecdh;
    int                   ret;
    
    p_ecdh = (mbedtls_ecdh_context*) p_context; 
    /**
     * For the MBEDTLS_ECP_DP_SECP256R1 the buffer must be equal to or larger
     * than 32 bytes.
     */
    // TODO: Magic number
    if (slen < 32u)
    {
        th_printf("e-[Secret buffer too small: %u < 32]\r\n", slen);
        return EE_STATUS_ERROR;
    }
    ret = mbedtls_ecdh_calc_secret(p_ecdh, &olen, p_secret, slen, NULL, NULL);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecdh_calc_secret: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR; 
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_status_t status;
    psa_ke_structure *context = (psa_ke_structure *) p_context;

    /* Produce ECDHE derived key */
    status = psa_raw_key_agreement( PSA_ALG_ECDH,                       // algorithm
                                    context->client_key_handle,         // client secret key
                                    context->p_public, context->publen, // server public key
                                    p_secret, slen,                     // buffer to store derived key
                                    &olen );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_raw_key_agreement: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR; 
    }
#endif /* CRYPTO_PSA */

    /**
     * Must be the same size as the curve size; for example, if the curve is 
     * secp256r1, secret must be 32 bytes long.
     */
    // TODO: Magic number
    if (olen != 32u)
    {
        th_printf("e-[Output length isn 32B: %lu]\r\n", olen);
        return EE_STATUS_ERROR; 
    }

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(
    void *p_context // input: portable context
)
{ 
#if defined(CRYPTO_MBEDTLS)
    mbedtls_ecdh_free((mbedtls_ecdh_context*)p_context);
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_ke_structure *context = (psa_ke_structure *) p_context;

    th_free(context->client_attributes);
    th_free(context->p_public);

    psa_destroy_key( context->client_key_handle );

    mbedtls_psa_crypto_free( );
#endif /* CRYPTO_PSA */

    th_free(p_context);
}
