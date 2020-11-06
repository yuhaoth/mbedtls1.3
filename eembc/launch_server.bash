#!/usr/bin/env bash

./ssl/ssl_server2 \
    debug_level=1 \
    server_port=8883 \
    server_addr=127.0.0.1 \
    force_version=tls1_3 \
    auth_mode=required \
    key_exchange_modes=ecdhe_ecdsa \
    cookies=0 \
    tickets=0 \
    ca_file=./certs256/ca.crt \
    crt_file=./certs256/server.crt \
    key_file=./certs256/server.key 

