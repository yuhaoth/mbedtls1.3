#!/bin/sh

# tls13-misc.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED

run_test    "TLS 1.3: PSK: No valid ciphersuite. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-CIPHER-ALL:+AES-256-GCM:+AEAD:+SHA384:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched ciphersuite"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED

run_test    "TLS 1.3: PSK: No valid ciphersuite. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex -ciphersuites TLS_AES_256_GCM_SHA384\
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched ciphersuite"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Multiple PSKs: valid ticket, reconnect with ticket" \
         "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 tickets=8" \
         "$P_CLI force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 2" \
         -s "sent selected_identity: 0" \
         -s "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "key exchange mode: ephemeral$" \
         -S "ticket is not authentic"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Multiple PSKs: invalid ticket, reconnect with PSK" \
         "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 tickets=8 dummy_ticket=1" \
         "$P_CLI force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 2" \
         -s "sent selected_identity: 1" \
         -s "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "key exchange mode: ephemeral$" \
         -s "ticket is not authentic"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, ticket authentication failed." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=8 dummy_ticket=1" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket start time" \
         -S "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, ticket expired." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=8 dummy_ticket=2" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -s "ticket is expired" \
         -S "Invalid ticket start time" \
         -S "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, invalid start time." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=8 dummy_ticket=3" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -s "Invalid ticket start time" \
         -S "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, ticket expired. too old" \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=8 dummy_ticket=4" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket start time" \
         -s "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, age outside tolerance window, too young." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=8 dummy_ticket=5" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket start time" \
         -S "Ticket age exceeds limitation" \
         -s "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, age outside tolerance window, too old." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=8 dummy_ticket=6" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket start time" \
         -S "Ticket age exceeds limitation" \
         -s "Ticket age outside tolerance window"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk, fail, no common kex mode" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
requires_all_configs_disabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
run_test    "TLS 1.3: G->m: PSK: configured psk only, good." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:+GROUP-ALL \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension"         \
            -s "Found PSK_EPHEMERAL KEX MODE"           \
            -s "Found PSK KEX MODE"                     \
            -s "key exchange mode: psk$"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
requires_all_configs_disabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
run_test    "TLS 1.3: G->m: PSK: configured psk_ephemeral only, good." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:+GROUP-ALL \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension"         \
            -s "Found PSK_EPHEMERAL KEX MODE"           \
            -s "Found PSK KEX MODE"                     \
            -s "key exchange mode: psk_ephemeral$"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_all_configs_disabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: G->m: PSK: configured ephemeral only, good." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:+GROUP-ALL \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "key exchange mode: ephemeral$"

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_EARLY_DATA
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: EarlyData: basic check, good" \
            "$G_NEXT_SRV -d 10 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:+ECDHE-PSK:+PSK --earlydata --disable-client-cert" \
            "$P_CLI debug_level=4 early_data=1 reco_mode=1 reconnect=1 reco_delay=2" \
            1 \
            -c "Reconnecting with saved session" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension exists." \
            -c "EncryptedExtensions: early_data(42) extension received." \
            -c "EncryptedExtensions: early_data(42) extension ( ignored )." \
            -s "Parsing extension 'Early Data/42' (0 bytes)" \
            -s "Sending extension Early Data/42 (0 bytes)" \
            -s "early data accepted"

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_EARLY_DATA
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: EarlyData: no early_data in NewSessionTicket, good" \
            "$G_NEXT_SRV -d 10 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:+ECDHE-PSK:+PSK --disable-client-cert" \
            "$P_CLI debug_level=4 early_data=1 reco_mode=1 reconnect=1 reco_delay=2" \
            0 \
            -c "Reconnecting with saved session" \
            -C "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension does not exist." \
            -C "EncryptedExtensions: early_data(42) extension received." \
            -C "EncryptedExtensions: early_data(42) extension ( ignored )."

#TODO: OpenSSL tests don't work now. It might be openssl options issue, cause GnuTLS has worked.
skip_next_test
requires_openssl_tls1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_EARLY_DATA
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3, ext PSK, early data" \
            "$O_NEXT_SRV_EARLY_DATA -msg -debug -tls1_3 -psk_identity 0a0b0c -psk 010203 -allow_no_dhe_kex -nocert" \
            "$P_CLI debug_level=5 force_version=tls13 tls13_kex_modes=psk early_data=1 psk=010203 psk_identity=0a0b0c" \
             1 \
            -c "Reconnecting with saved session" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension exists." \
            -c "EncryptedExtensions: early_data(42) extension received." \
            -c "EncryptedExtensions: early_data(42) extension ( ignored )."

requires_gnutls_next
requires_config_disabled MBEDTLS_SSL_EARLY_DATA
requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C  \
                             MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME              \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: ephemeral: feature unavailable, good." \
         "$P_SRV force_version=tls13 reco_debug_level=4" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL \
                      -d 10 -r --earlydata $EARLY_DATA_INPUT" \
         0 \
         -c "This is a resumed session"                                     \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension does not exist." \
         -s "Ignore application message"

requires_gnutls_next
requires_config_disabled MBEDTLS_SSL_EARLY_DATA
requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C  \
                             MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: psk*: feature unavailable, good." \
         "$P_SRV force_version=tls13 debug_level=4 $(get_srv_psk_list)" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK \
                      -d 10 -r --earlydata $EARLY_DATA_INPUT \
                      --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70" \
         0 \
         -c "This is a resumed session"                                     \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension does not exist." \
         -s "Ignore application message"

requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS     \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME    \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: ephemeral: feature is disabled, good." \
         "$P_SRV force_version=tls13 reco_debug_level=4" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL -d 10 -r --earlydata $EARLY_DATA_INPUT" \
         0 \
         -c "This is a resumed session"                                     \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension does not exist." \
         -s "Ignore application message"

requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS     \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME    \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: psk*: feature is disabled, good." \
         "$P_SRV force_version=tls13 reco_debug_level=4 $(get_srv_psk_list)" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK \
                      -d 10 -r --earlydata $EARLY_DATA_INPUT \
                      --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70" \
         0 \
         -c "This is a resumed session"                                     \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension does not exist." \
         -s "Ignore application message"

EARLY_DATA_INPUT_LEN=$( cat $EARLY_DATA_INPUT | wc -c )
MAX_EARLY_DATA_SIZE=$(( 1024 > $EARLY_DATA_INPUT_LEN ? 1024 : $EARLY_DATA_INPUT_LEN ))

requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: ephemeral: all data is accepted, good." \
         "$P_SRV force_version=tls13 reco_debug_level=5 max_early_data_size=$MAX_EARLY_DATA_SIZE" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL -d 10 -r --earlydata $EARLY_DATA_INPUT" \
         0 \
         -c "This is a resumed session"                                     \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension exists."         \
         -s "$( cat $EARLY_DATA_INPUT )"                                    \
         -s "ssl->conf->max_early_data_size=$MAX_EARLY_DATA_SIZE"           \
         -S "Ignore application message"


requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: psk*: all data is accepted, good." \
         "$P_SRV force_version=tls13 reco_debug_level=4 max_early_data_size=$MAX_EARLY_DATA_SIZE $(get_srv_psk_list)" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK \
                      -d 10 -r --earlydata $EARLY_DATA_INPUT \
                      --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70" \
         0 \
         -c "This is a resumed session"                                     \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension exists."         \
         -s "$( cat $EARLY_DATA_INPUT )"                                    \
         -s "ssl->conf->max_early_data_size=$MAX_EARLY_DATA_SIZE"           \
         -S "Ignore application message"

EARLY_DATA_INPUT_LINE1_LEN=$(head -1 $EARLY_DATA_INPUT | wc -c)
requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: ephemeral: size exceeds the limit, fail." \
         "$P_SRV force_version=tls13 debug_level=5 max_early_data_size=$EARLY_DATA_INPUT_LINE1_LEN" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL -d 10 -r --earlydata $EARLY_DATA_INPUT" \
         1 \
         -s "unexpected message was received"                               \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension exists."         \
         -s "ssl->conf->max_early_data_size=$EARLY_DATA_INPUT_LINE1_LEN"    \
         -S "Ignore application message"

requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: psk*: size exceeds the limit, fail." \
         "$P_SRV force_version=tls13 debug_level=4 max_early_data_size=$EARLY_DATA_INPUT_LINE1_LEN $(get_srv_psk_list)" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK \
                      -d 10 -r --earlydata $EARLY_DATA_INPUT \
                      --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70" \
         1 \
         -s "unexpected message was received"                               \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension exists."         \
         -s "ssl->conf->max_early_data_size=$EARLY_DATA_INPUT_LINE1_LEN"    \
         -S "Ignore application message"


requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: HRR check, enabled. good." \
         "$P_SRV force_version=tls13 reco_debug_level=4 reco_group=secp384r1 max_early_data_size=1024" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1 -d 10 -r --earlydata data_files/early_data.txt" \
         1 \
         -s "ClientHello: early_data(42) extension received." \
         -s "tls13 server state: MBEDTLS_SSL_HELLO_RETRY_REQUEST" \
         -s "ClientHello: early_data(42) extension does not exist."

requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: HRR check, disabled. good." \
         "$P_SRV force_version=tls13 reco_debug_level=4 reco_group=secp384r1 max_early_data_size=0" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1 -d 10 -r --earlydata data_files/early_data.txt" \
         1 \
         -s "ClientHello: early_data(42) extension received." \
         -s "tls13 server state: MBEDTLS_SSL_HELLO_RETRY_REQUEST" \
         -s "ClientHello: early_data(42) extension does not exist."


