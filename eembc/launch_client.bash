#!/usr/bin/env bash

./ssl/ssl_client2 \
    debug_level=9 \
    server_port=8883 \
    server_addr=127.0.0.1 \
    force_version=tls1_3 \
    ca_file=./certs256/ca.crt \
    crt_file=./certs256/client.crt \
    key_file=./certs256/client.key \
    force_ciphersuite=TLS_AES_128_GCM_SHA256 \
    auth_mode=required \
    key_exchange_modes=ecdhe_ecdsa \
    named_groups=secp256r1 \
    key_share_named_groups=secp256r1 \
    sig_algs=ecdsa_secp256r1_sha256

