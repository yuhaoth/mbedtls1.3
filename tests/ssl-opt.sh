#!/bin/sh

# ssl-opt.sh
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
# Purpose
#
# Executes tests to prove various TLS/SSL options and extensions.
#
# The goal is not to cover every ciphersuite/version, but instead to cover
# specific options (max fragment length, truncated hmac, etc) or procedures
# (session resumption from cache or ticket, renego, etc).
#
# The tests assume a build with default options, with exceptions expressed
# with a dependency.  The tests focus on functionality and do not consider
# performance.
#

set -u

# Limit the size of each log to 10 GiB, in case of failures with this script
# where it may output seemingly unlimited length error logs.
ulimit -f 20971520

ORIGINAL_PWD=$PWD
if ! cd "$(dirname "$0")"; then
    exit 125
fi

# default values, can be overridden by the environment
: ${P_SRV:=../programs/ssl/ssl_server2}
: ${P_CLI:=../programs/ssl/ssl_client2}
: ${P_PXY:=../programs/test/udp_proxy}
: ${P_QUERY:=../programs/test/query_compile_time_config}
: ${OPENSSL_CMD:=openssl} # OPENSSL would conflict with the build system
: ${GNUTLS_CLI:=gnutls-cli}
: ${GNUTLS_SERV:=gnutls-serv}
: ${PERL:=perl}
: ${SUBDIRECTORY:=opt-testcases}

guess_config_name() {
    if git diff --quiet ../include/mbedtls/mbedtls_config.h 2>/dev/null; then
        echo "default"
    else
        echo "unknown"
    fi
}
: ${MBEDTLS_TEST_OUTCOME_FILE=}
: ${MBEDTLS_TEST_CONFIGURATION:="$(guess_config_name)"}
: ${MBEDTLS_TEST_PLATFORM:="$(uname -s | tr -c \\n0-9A-Za-z _)-$(uname -m | tr -c \\n0-9A-Za-z _)"}

O_SRV="$OPENSSL_CMD s_server -www -cert data_files/server5.crt -key data_files/server5.key"
O_CLI="echo 'GET / HTTP/1.0' | $OPENSSL_CMD s_client"
G_SRV="$GNUTLS_SERV --x509certfile data_files/server5.crt --x509keyfile data_files/server5.key"
G_CLI="echo 'GET / HTTP/1.0' | $GNUTLS_CLI --x509cafile data_files/test-ca_cat12.crt"
TCP_CLIENT="$PERL scripts/tcp_client.pl"

# alternative versions of OpenSSL and GnuTLS (no default path)

if [ -n "${OPENSSL_LEGACY:-}" ]; then
    O_LEGACY_SRV="$OPENSSL_LEGACY s_server -www -cert data_files/server5.crt -key data_files/server5.key"
    O_LEGACY_CLI="echo 'GET / HTTP/1.0' | $OPENSSL_LEGACY s_client"
else
    O_LEGACY_SRV=false
    O_LEGACY_CLI=false
fi

if [ -n "${OPENSSL_NEXT:-}" ]; then
    O_NEXT_SRV="$OPENSSL_NEXT s_server -www -cert data_files/server5.crt -key data_files/server5.key"
    O_NEXT_SRV_NO_CERT="$OPENSSL_NEXT s_server -www "
    O_NEXT_CLI="echo 'GET / HTTP/1.0' | $OPENSSL_NEXT s_client"
else
    O_NEXT_SRV=false
    O_NEXT_SRV_NO_CERT=false
    O_NEXT_CLI=false
fi

if [ -n "${GNUTLS_NEXT_SERV:-}" ]; then
    G_NEXT_SRV="$GNUTLS_NEXT_SERV --x509certfile data_files/server5.crt --x509keyfile data_files/server5.key"
    G_NEXT_SRV_NO_CERT="$GNUTLS_NEXT_SERV"
else
    G_NEXT_SRV=false
    G_NEXT_SRV_NO_CERT=false
fi

if [ -n "${GNUTLS_NEXT_CLI:-}" ]; then
    G_NEXT_CLI="echo 'GET / HTTP/1.0' | $GNUTLS_NEXT_CLI --x509cafile data_files/test-ca_cat12.crt"
else
    G_NEXT_CLI=false
fi

TESTS=0
FAILS=0
SKIPS=0

CONFIG_H='../include/mbedtls/mbedtls_config.h'

MEMCHECK=0
FILTER='.*'
EXCLUDE='^$'

SHOW_TEST_NUMBER=0
RUN_TEST_NUMBER=''

PRESERVE_LOGS=0

# Pick a "unique" server port in the range 10000-19999, and a proxy
# port which is this plus 10000. Each port number may be independently
# overridden by a command line option.
SRV_PORT=$(($$ % 10000 + 10000))
PXY_PORT=$((SRV_PORT + 10000))

print_usage() {
    echo "Usage: $0 [options]"
    printf "  -h|--help\tPrint this help.\n"
    printf "  -m|--memcheck\tCheck memory leaks and errors.\n"
    printf "  -f|--filter\tOnly matching tests are executed (substring or BRE)\n"
    printf "  -e|--exclude\tMatching tests are excluded (substring or BRE)\n"
    printf "  -n|--number\tExecute only numbered test (comma-separated, e.g. '245,256')\n"
    printf "  -s|--show-numbers\tShow test numbers in front of test names\n"
    printf "  -p|--preserve-logs\tPreserve logs of successful tests as well\n"
    printf "     --outcome-file\tFile where test outcomes are written\n"
    printf "                \t(default: \$MBEDTLS_TEST_OUTCOME_FILE, none if empty)\n"
    printf "     --port     \tTCP/UDP port (default: randomish 1xxxx)\n"
    printf "     --proxy-port\tTCP/UDP proxy port (default: randomish 2xxxx)\n"
    printf "     --seed     \tInteger seed value to use for this test run\n"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--filter)
                shift; FILTER=$1
                ;;
            -e|--exclude)
                shift; EXCLUDE=$1
                ;;
            -m|--memcheck)
                MEMCHECK=1
                ;;
            -n|--number)
                shift; RUN_TEST_NUMBER=$1
                ;;
            -s|--show-numbers)
                SHOW_TEST_NUMBER=1
                ;;
            -p|--preserve-logs)
                PRESERVE_LOGS=1
                ;;
            --port)
                shift; SRV_PORT=$1
                ;;
            --proxy-port)
                shift; PXY_PORT=$1
                ;;
            --seed)
                shift; SEED="$1"
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown argument: '$1'"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

# Make the outcome file path relative to the original directory, not
# to .../tests
case "$MBEDTLS_TEST_OUTCOME_FILE" in
    [!/]*)
        MBEDTLS_TEST_OUTCOME_FILE="$ORIGINAL_PWD/$MBEDTLS_TEST_OUTCOME_FILE"
        ;;
esac

# Read boolean configuration options from mbedtls_config.h for easy and quick
# testing. Skip non-boolean options (with something other than spaces
# and a comment after "#define SYMBOL"). The variable contains a
# space-separated list of symbols.
CONFIGS_ENABLED=" $(echo `$P_QUERY -l` )"
# Skip next test; use this macro to skip tests which are legitimate
# in theory and expected to be re-introduced at some point, but
# aren't expected to succeed at the moment due to problems outside
# our control (such as bugs in other TLS implementations).
skip_next_test() {
    SKIP_NEXT="YES"
}

# skip next test if the flag is not enabled in mbedtls_config.h
requires_config_enabled() {
    case $CONFIGS_ENABLED in
        *" $1"[\ =]*) :;;
        *) SKIP_NEXT="YES";;
    esac
}

# skip next test if the flag is enabled in mbedtls_config.h
requires_config_disabled() {
    case $CONFIGS_ENABLED in
        *" $1"[\ =]*) SKIP_NEXT="YES";;
    esac
}

get_config_value_or_default() {
    # This function uses the query_config command line option to query the
    # required Mbed TLS compile time configuration from the ssl_server2
    # program. The command will always return a success value if the
    # configuration is defined and the value will be printed to stdout.
    #
    # Note that if the configuration is not defined or is defined to nothing,
    # the output of this function will be an empty string.
    ${P_SRV} "query_config=${1}"
}

requires_config_value_at_least() {
    VAL="$( get_config_value_or_default "$1" )"
    if [ -z "$VAL" ]; then
        # Should never happen
        echo "Mbed TLS configuration $1 is not defined"
        exit 1
    elif [ "$VAL" -lt "$2" ]; then
       SKIP_NEXT="YES"
    fi
}

requires_config_value_at_most() {
    VAL=$( get_config_value_or_default "$1" )
    if [ -z "$VAL" ]; then
        # Should never happen
        echo "Mbed TLS configuration $1 is not defined"
        exit 1
    elif [ "$VAL" -gt "$2" ]; then
       SKIP_NEXT="YES"
    fi
}

requires_config_value_equals() {
    VAL=$( get_config_value_or_default "$1" )
    if [ -z "$VAL" ]; then
        # Should never happen
        echo "Mbed TLS configuration $1 is not defined"
        exit 1
    elif [ "$VAL" -ne "$2" ]; then
       SKIP_NEXT="YES"
    fi
}

# Space-separated list of ciphersuites supported by this build of
# Mbed TLS.
P_CIPHERSUITES=" $($P_CLI --help 2>/dev/null |
                   grep 'TLS-\|TLS1-3' |
                   tr -s ' \n' ' ')"
requires_ciphersuite_enabled() {
    case $P_CIPHERSUITES in
        *" $1 "*) :;;
        *) SKIP_NEXT="YES";;
    esac
}

# maybe_requires_ciphersuite_enabled CMD [RUN_TEST_OPTION...]
# If CMD (call to a TLS client or server program) requires a specific
# ciphersuite, arrange to only run the test case if this ciphersuite is
# enabled.
maybe_requires_ciphersuite_enabled() {
    case "$1" in
        *\ force_ciphersuite=*) :;;
        *) return;; # No specific required ciphersuite
    esac
    ciphersuite="${1##*\ force_ciphersuite=}"
    ciphersuite="${ciphersuite%%[!-0-9A-Z_a-z]*}"
    shift

    requires_ciphersuite_enabled "$ciphersuite"

    unset ciphersuite
}

# skip next test if OpenSSL doesn't support FALLBACK_SCSV
requires_openssl_with_fallback_scsv() {
    if [ -z "${OPENSSL_HAS_FBSCSV:-}" ]; then
        if $OPENSSL_CMD s_client -help 2>&1 | grep fallback_scsv >/dev/null
        then
            OPENSSL_HAS_FBSCSV="YES"
        else
            OPENSSL_HAS_FBSCSV="NO"
        fi
    fi
    if [ "$OPENSSL_HAS_FBSCSV" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if either IN_CONTENT_LEN or MAX_CONTENT_LEN are below a value
requires_max_content_len() {
    requires_config_value_at_least "MBEDTLS_SSL_IN_CONTENT_LEN" $1
    requires_config_value_at_least "MBEDTLS_SSL_OUT_CONTENT_LEN" $1
}

# skip next test if GnuTLS isn't available
requires_gnutls() {
    if [ -z "${GNUTLS_AVAILABLE:-}" ]; then
        if ( which "$GNUTLS_CLI" && which "$GNUTLS_SERV" ) >/dev/null 2>&1; then
            GNUTLS_AVAILABLE="YES"
        else
            GNUTLS_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if GnuTLS-next isn't available
requires_gnutls_next() {
    if [ -z "${GNUTLS_NEXT_AVAILABLE:-}" ]; then
        if ( which "${GNUTLS_NEXT_CLI:-}" && which "${GNUTLS_NEXT_SERV:-}" ) >/dev/null 2>&1; then
            GNUTLS_NEXT_AVAILABLE="YES"
        else
            GNUTLS_NEXT_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_NEXT_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if OpenSSL-legacy isn't available
requires_openssl_legacy() {
    if [ -z "${OPENSSL_LEGACY_AVAILABLE:-}" ]; then
        if which "${OPENSSL_LEGACY:-}" >/dev/null 2>&1; then
            OPENSSL_LEGACY_AVAILABLE="YES"
        else
            OPENSSL_LEGACY_AVAILABLE="NO"
        fi
    fi
    if [ "$OPENSSL_LEGACY_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

requires_openssl_next() {
    if [ -z "${OPENSSL_NEXT_AVAILABLE:-}" ]; then
        if which "${OPENSSL_NEXT:-}" >/dev/null 2>&1; then
            OPENSSL_NEXT_AVAILABLE="YES"
        else
            OPENSSL_NEXT_AVAILABLE="NO"
        fi
    fi
    if [ "$OPENSSL_NEXT_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if tls1_3 is not available
requires_openssl_tls1_3() {
    requires_openssl_next
    if [ "$OPENSSL_NEXT_AVAILABLE" = "NO" ]; then
        OPENSSL_TLS1_3_AVAILABLE="NO"
    fi
    if [ -z "${OPENSSL_TLS1_3_AVAILABLE:-}" ]; then
        if $OPENSSL_NEXT s_client -help 2>&1 | grep tls1_3 >/dev/null
        then
            OPENSSL_TLS1_3_AVAILABLE="YES"
        else
            OPENSSL_TLS1_3_AVAILABLE="NO"
        fi
    fi
    if [ "$OPENSSL_TLS1_3_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if tls1_3 is not available
requires_gnutls_tls1_3() {
    requires_gnutls_next
    if [ "$GNUTLS_NEXT_AVAILABLE" = "NO" ]; then
        GNUTLS_TLS1_3_AVAILABLE="NO"
    fi
    if [ -z "${GNUTLS_TLS1_3_AVAILABLE:-}" ]; then
        if $GNUTLS_NEXT_CLI -l 2>&1 | grep VERS-TLS1.3 >/dev/null
        then
            GNUTLS_TLS1_3_AVAILABLE="YES"
        else
            GNUTLS_TLS1_3_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_TLS1_3_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# Check %NO_TICKETS option
requires_gnutls_next_no_ticket() {
    requires_gnutls_next
    if [ "$GNUTLS_NEXT_AVAILABLE" = "NO" ]; then
        GNUTLS_NO_TICKETS_AVAILABLE="NO"
    fi
    if [ -z "${GNUTLS_NO_TICKETS_AVAILABLE:-}" ]; then
        if $GNUTLS_NEXT_CLI --priority-list 2>&1 | grep NO_TICKETS >/dev/null
        then
            GNUTLS_NO_TICKETS_AVAILABLE="YES"
        else
            GNUTLS_NO_TICKETS_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_NO_TICKETS_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# Check %DISABLE_TLS13_COMPAT_MODE option
requires_gnutls_next_disable_tls13_compat() {
    requires_gnutls_next
    if [ "$GNUTLS_NEXT_AVAILABLE" = "NO" ]; then
        GNUTLS_DISABLE_TLS13_COMPAT_MODE_AVAILABLE="NO"
    fi
    if [ -z "${GNUTLS_DISABLE_TLS13_COMPAT_MODE_AVAILABLE:-}" ]; then
        if $GNUTLS_NEXT_CLI --priority-list 2>&1 | grep DISABLE_TLS13_COMPAT_MODE >/dev/null
        then
            GNUTLS_DISABLE_TLS13_COMPAT_MODE_AVAILABLE="YES"
        else
            GNUTLS_DISABLE_TLS13_COMPAT_MODE_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_DISABLE_TLS13_COMPAT_MODE_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if IPv6 isn't available on this host
requires_ipv6() {
    if [ -z "${HAS_IPV6:-}" ]; then
        $P_SRV server_addr='::1' > $SRV_OUT 2>&1 &
        SRV_PID=$!
        sleep 1
        kill $SRV_PID >/dev/null 2>&1
        if grep "NET - Binding of the socket failed" $SRV_OUT >/dev/null; then
            HAS_IPV6="NO"
        else
            HAS_IPV6="YES"
        fi
        rm -r $SRV_OUT
    fi

    if [ "$HAS_IPV6" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if it's i686 or uname is not available
requires_not_i686() {
    if [ -z "${IS_I686:-}" ]; then
        IS_I686="YES"
        if which "uname" >/dev/null 2>&1; then
            if [ -z "$(uname -a | grep i686)" ]; then
                IS_I686="NO"
            fi
        fi
    fi
    if [ "$IS_I686" = "YES" ]; then
        SKIP_NEXT="YES"
    fi
}

# Calculate the input & output maximum content lengths set in the config
MAX_CONTENT_LEN=16384
MAX_IN_LEN=$( get_config_value_or_default "MBEDTLS_SSL_IN_CONTENT_LEN" )
MAX_OUT_LEN=$( get_config_value_or_default "MBEDTLS_SSL_OUT_CONTENT_LEN" )

# Calculate the maximum content length that fits both
if [ "$MAX_IN_LEN" -lt "$MAX_CONTENT_LEN" ]; then
    MAX_CONTENT_LEN="$MAX_IN_LEN"
fi
if [ "$MAX_OUT_LEN" -lt "$MAX_CONTENT_LEN" ]; then
    MAX_CONTENT_LEN="$MAX_OUT_LEN"
fi

# skip the next test if the SSL output buffer is less than 16KB
requires_full_size_output_buffer() {
    if [ "$MAX_OUT_LEN" -ne 16384 ]; then
        SKIP_NEXT="YES"
    fi
}

# skip the next test if valgrind is in use
not_with_valgrind() {
    if [ "$MEMCHECK" -gt 0 ]; then
        SKIP_NEXT="YES"
    fi
}

# skip the next test if valgrind is NOT in use
only_with_valgrind() {
    if [ "$MEMCHECK" -eq 0 ]; then
        SKIP_NEXT="YES"
    fi
}

# multiply the client timeout delay by the given factor for the next test
client_needs_more_time() {
    CLI_DELAY_FACTOR=$1
}

# wait for the given seconds after the client finished in the next test
server_needs_more_time() {
    SRV_DELAY_SECONDS=$1
}

# print_name <name>
print_name() {
    TESTS=$(( $TESTS + 1 ))
    LINE=""

    if [ "$SHOW_TEST_NUMBER" -gt 0 ]; then
        LINE="$TESTS "
    fi

    LINE="$LINE$1"
    printf "%s " "$LINE"
    LEN=$(( 72 - `echo "$LINE" | wc -c` ))
    for i in `seq 1 $LEN`; do printf '.'; done
    printf ' '

}

# record_outcome <outcome> [<failure-reason>]
# The test name must be in $NAME.
record_outcome() {
    echo "$1"
    if [ -n "$MBEDTLS_TEST_OUTCOME_FILE" ]; then
        printf '%s;%s;%s;%s;%s;%s\n' \
               "$MBEDTLS_TEST_PLATFORM" "$MBEDTLS_TEST_CONFIGURATION" \
               "ssl-opt" "$NAME" \
               "$1" "${2-}" \
               >>"$MBEDTLS_TEST_OUTCOME_FILE"
    fi
}

# True if the presence of the given pattern in a log definitely indicates
# that the test has failed. False if the presence is inconclusive.
#
# Inputs:
# * $1: pattern found in the logs
# * $TIMES_LEFT: >0 if retrying is an option
#
# Outputs:
# * $outcome: set to a retry reason if the pattern is inconclusive,
#             unchanged otherwise.
# * Return value: 1 if the pattern is inconclusive,
#                 0 if the failure is definitive.
log_pattern_presence_is_conclusive() {
    # If we've run out of attempts, then don't retry no matter what.
    if [ $TIMES_LEFT -eq 0 ]; then
        return 0
    fi
    case $1 in
        "resend")
            # An undesired resend may have been caused by the OS dropping or
            # delaying a packet at an inopportune time.
            outcome="RETRY(resend)"
            return 1;;
    esac
}

# fail <message>
fail() {
    record_outcome "FAIL" "$1"
    echo "  ! $1"

    mv $SRV_OUT o-srv-${TESTS}.log
    mv $CLI_OUT o-cli-${TESTS}.log
    if [ -n "$PXY_CMD" ]; then
        mv $PXY_OUT o-pxy-${TESTS}.log
    fi
    echo "  ! outputs saved to o-XXX-${TESTS}.log"

    if [ "${LOG_FAILURE_ON_STDOUT:-0}" != 0 ]; then
        echo "  ! server output:"
        cat o-srv-${TESTS}.log
        echo "  ! ========================================================"
        echo "  ! client output:"
        cat o-cli-${TESTS}.log
        if [ -n "$PXY_CMD" ]; then
            echo "  ! ========================================================"
            echo "  ! proxy output:"
            cat o-pxy-${TESTS}.log
        fi
        echo ""
    fi

    FAILS=$(( $FAILS + 1 ))
}

# is_polar <cmd_line>
is_polar() {
    case "$1" in
        *ssl_client2*) true;;
        *ssl_server2*) true;;
        *) false;;
    esac
}

# openssl s_server doesn't have -www with DTLS
check_osrv_dtls() {
    case "$SRV_CMD" in
        *s_server*-dtls*)
            NEEDS_INPUT=1
            SRV_CMD="$( echo $SRV_CMD | sed s/-www// )";;
        *) NEEDS_INPUT=0;;
    esac
}

# provide input to commands that need it
provide_input() {
    if [ $NEEDS_INPUT -eq 0 ]; then
        return
    fi

    while true; do
        echo "HTTP/1.0 200 OK"
        sleep 1
    done
}

# has_mem_err <log_file_name>
has_mem_err() {
    if ( grep -F 'All heap blocks were freed -- no leaks are possible' "$1" &&
         grep -F 'ERROR SUMMARY: 0 errors from 0 contexts' "$1" ) > /dev/null
    then
        return 1 # false: does not have errors
    else
        return 0 # true: has errors
    fi
}

# Wait for process $2 named $3 to be listening on port $1. Print error to $4.
if type lsof >/dev/null 2>/dev/null; then
    wait_app_start() {
        newline='
'
        START_TIME=$(date +%s)
        if [ "$DTLS" -eq 1 ]; then
            proto=UDP
        else
            proto=TCP
        fi
        # Make a tight loop, server normally takes less than 1s to start.
        while true; do
              SERVER_PIDS=$(lsof -a -n -b -i "$proto:$1" -F p)
              # When we use a proxy, it will be listening on the same port we
              # are checking for as well as the server and lsof will list both.
              # If multiple PIDs are returned, each one will be on a separate
              # line, each prepended with 'p'.
             case ${newline}${SERVER_PIDS}${newline} in
                  *${newline}p${2}${newline}*) break;;
              esac
              if [ $(( $(date +%s) - $START_TIME )) -gt $DOG_DELAY ]; then
                  echo "$3 START TIMEOUT"
                  echo "$3 START TIMEOUT" >> $4
                  break
              fi
              # Linux and *BSD support decimal arguments to sleep. On other
              # OSes this may be a tight loop.
              sleep 0.1 2>/dev/null || true
        done
    }
else
    echo "Warning: lsof not available, wait_app_start = sleep"
    wait_app_start() {
        sleep "$START_DELAY"
    }
fi

# Wait for server process $2 to be listening on port $1.
wait_server_start() {
    wait_app_start $1 $2 "SERVER" $SRV_OUT
}

# Wait for proxy process $2 to be listening on port $1.
wait_proxy_start() {
    wait_app_start $1 $2 "PROXY" $PXY_OUT
}

# Given the client or server debug output, parse the unix timestamp that is
# included in the first 4 bytes of the random bytes and check that it's within
# acceptable bounds
check_server_hello_time() {
    # Extract the time from the debug (lvl 3) output of the client
    SERVER_HELLO_TIME="$(sed -n 's/.*server hello, current time: //p' < "$1")"
    # Get the Unix timestamp for now
    CUR_TIME=$(date +'%s')
    THRESHOLD_IN_SECS=300

    # Check if the ServerHello time was printed
    if [ -z "$SERVER_HELLO_TIME" ]; then
        return 1
    fi

    # Check the time in ServerHello is within acceptable bounds
    if [ $SERVER_HELLO_TIME -lt $(( $CUR_TIME - $THRESHOLD_IN_SECS )) ]; then
        # The time in ServerHello is at least 5 minutes before now
        return 1
    elif [ $SERVER_HELLO_TIME -gt $(( $CUR_TIME + $THRESHOLD_IN_SECS )) ]; then
        # The time in ServerHello is at least 5 minutes later than now
        return 1
    else
        return 0
    fi
}

# wait for client to terminate and set CLI_EXIT
# must be called right after starting the client
wait_client_done() {
    CLI_PID=$!

    CLI_DELAY=$(( $DOG_DELAY * $CLI_DELAY_FACTOR ))
    CLI_DELAY_FACTOR=1

    ( sleep $CLI_DELAY; echo "===CLIENT_TIMEOUT===" >> $CLI_OUT; kill $CLI_PID ) &
    DOG_PID=$!

    wait $CLI_PID
    CLI_EXIT=$?

    kill $DOG_PID >/dev/null 2>&1
    wait $DOG_PID

    echo "EXIT: $CLI_EXIT" >> $CLI_OUT

    sleep $SRV_DELAY_SECONDS
    SRV_DELAY_SECONDS=0
}

# check if the given command uses dtls and sets global variable DTLS
detect_dtls() {
    case "$1" in
        *dtls=1*|*-dtls*|*-u*) DTLS=1;;
        *) DTLS=0;;
    esac
}

# check if the given command uses gnutls and sets global variable CMD_IS_GNUTLS
is_gnutls() {
    case "$1" in
    *gnutls-cli*)
        CMD_IS_GNUTLS=1
        ;;
    *gnutls-serv*)
        CMD_IS_GNUTLS=1
        ;;
    *)
        CMD_IS_GNUTLS=0
        ;;
    esac
}

# Compare file content
# Usage: find_in_both pattern file1 file2
# extract from file1 the first line matching the pattern
# check in file2 that the same line can be found
find_in_both() {
        srv_pattern=$(grep -m 1 "$1" "$2");
        if [ -z "$srv_pattern" ]; then
                return 1;
        fi

        if grep "$srv_pattern" $3 >/dev/null; then :
                return 0;
        else
                return 1;
        fi
}

SKIP_HANDSHAKE_CHECK="NO"
skip_handshake_stage_check() {
    SKIP_HANDSHAKE_CHECK="YES"
}

# Analyze the commands that will be used in a test.
#
# Analyze and possibly instrument $PXY_CMD, $CLI_CMD, $SRV_CMD to pass
# extra arguments or go through wrappers.
# Set $DTLS (0=TLS, 1=DTLS).
analyze_test_commands() {
    # update DTLS variable
    detect_dtls "$SRV_CMD"

    # if the test uses DTLS but no custom proxy, add a simple proxy
    # as it provides timing info that's useful to debug failures
    if [ -z "$PXY_CMD" ] && [ "$DTLS" -eq 1 ]; then
        PXY_CMD="$P_PXY"
        case " $SRV_CMD " in
            *' server_addr=::1 '*)
                PXY_CMD="$PXY_CMD server_addr=::1 listen_addr=::1";;
        esac
    fi

    # update CMD_IS_GNUTLS variable
    is_gnutls "$SRV_CMD"

    # if the server uses gnutls but doesn't set priority, explicitly
    # set the default priority
    if [ "$CMD_IS_GNUTLS" -eq 1 ]; then
        case "$SRV_CMD" in
              *--priority*) :;;
              *) SRV_CMD="$SRV_CMD --priority=NORMAL";;
        esac
    fi

    # update CMD_IS_GNUTLS variable
    is_gnutls "$CLI_CMD"

    # if the client uses gnutls but doesn't set priority, explicitly
    # set the default priority
    if [ "$CMD_IS_GNUTLS" -eq 1 ]; then
        case "$CLI_CMD" in
              *--priority*) :;;
              *) CLI_CMD="$CLI_CMD --priority=NORMAL";;
        esac
    fi

    # fix client port
    if [ -n "$PXY_CMD" ]; then
        CLI_CMD=$( echo "$CLI_CMD" | sed s/+SRV_PORT/$PXY_PORT/g )
    else
        CLI_CMD=$( echo "$CLI_CMD" | sed s/+SRV_PORT/$SRV_PORT/g )
    fi

    # prepend valgrind to our commands if active
    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SRV_CMD"; then
            SRV_CMD="valgrind --leak-check=full $SRV_CMD"
        fi
        if is_polar "$CLI_CMD"; then
            CLI_CMD="valgrind --leak-check=full $CLI_CMD"
        fi
    fi
}

# Check for failure conditions after a test case.
#
# Inputs from run_test:
# * positional parameters: test options (see run_test documentation)
# * $CLI_EXIT: client return code
# * $CLI_EXPECT: expected client return code
# * $SRV_RET: server return code
# * $CLI_OUT, $SRV_OUT, $PXY_OUT: files containing client/server/proxy logs
# * $TIMES_LEFT: if nonzero, a RETRY outcome is allowed
#
# Outputs:
# * $outcome: one of PASS/RETRY*/FAIL
check_test_failure() {
    outcome=FAIL

    if [ $TIMES_LEFT -gt 0 ] &&
       grep '===CLIENT_TIMEOUT===' $CLI_OUT >/dev/null
    then
        outcome="RETRY(client-timeout)"
        return
    fi

    # check if the client and server went at least to the handshake stage
    # (useful to avoid tests with only negative assertions and non-zero
    # expected client exit to incorrectly succeed in case of catastrophic
    # failure)
    if [ "X$SKIP_HANDSHAKE_CHECK" != "XYES" ]
    then
        if is_polar "$SRV_CMD"; then
            if grep "Performing the SSL/TLS handshake" $SRV_OUT >/dev/null; then :;
            else
                fail "server or client failed to reach handshake stage"
                return
            fi
        fi
        if is_polar "$CLI_CMD"; then
            if grep "Performing the SSL/TLS handshake" $CLI_OUT >/dev/null; then :;
            else
                fail "server or client failed to reach handshake stage"
                return
            fi
        fi
    fi

    SKIP_HANDSHAKE_CHECK="NO"
    # Check server exit code (only for Mbed TLS: GnuTLS and OpenSSL don't
    # exit with status 0 when interrupted by a signal, and we don't really
    # care anyway), in case e.g. the server reports a memory leak.
    if [ $SRV_RET != 0 ] && is_polar "$SRV_CMD"; then
        fail "Server exited with status $SRV_RET"
        return
    fi

    # check client exit code
    if [ \( "$CLI_EXPECT" = 0 -a "$CLI_EXIT" != 0 \) -o \
         \( "$CLI_EXPECT" != 0 -a "$CLI_EXIT" = 0 \) ]
    then
        fail "bad client exit code (expected $CLI_EXPECT, got $CLI_EXIT)"
        return
    fi

    # check other assertions
    # lines beginning with == are added by valgrind, ignore them
    # lines with 'Serious error when reading debug info', are valgrind issues as well
    while [ $# -gt 0 ]
    do
        case $1 in
            "-s")
                if grep -v '^==' $SRV_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then :; else
                    fail "pattern '$2' MUST be present in the Server output"
                    return
                fi
                ;;

            "-c")
                if grep -v '^==' $CLI_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then :; else
                    fail "pattern '$2' MUST be present in the Client output"
                    return
                fi
                ;;

            "-S")
                if grep -v '^==' $SRV_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then
                    if log_pattern_presence_is_conclusive "$2"; then
                        fail "pattern '$2' MUST NOT be present in the Server output"
                    fi
                    return
                fi
                ;;

            "-C")
                if grep -v '^==' $CLI_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then
                    if log_pattern_presence_is_conclusive "$2"; then
                        fail "pattern '$2' MUST NOT be present in the Client output"
                    fi
                    return
                fi
                ;;

                # The filtering in the following two options (-u and -U) do the following
                #   - ignore valgrind output
                #   - filter out everything but lines right after the pattern occurrences
                #   - keep one of each non-unique line
                #   - count how many lines remain
                # A line with '--' will remain in the result from previous outputs, so the number of lines in the result will be 1
                # if there were no duplicates.
            "-U")
                if [ $(grep -v '^==' $SRV_OUT | grep -v 'Serious error when reading debug info' | grep -A1 "$2" | grep -v "$2" | sort | uniq -d | wc -l) -gt 1 ]; then
                    fail "lines following pattern '$2' must be unique in Server output"
                    return
                fi
                ;;

            "-u")
                if [ $(grep -v '^==' $CLI_OUT | grep -v 'Serious error when reading debug info' | grep -A1 "$2" | grep -v "$2" | sort | uniq -d | wc -l) -gt 1 ]; then
                    fail "lines following pattern '$2' must be unique in Client output"
                    return
                fi
                ;;
            "-F")
                if ! $2 "$SRV_OUT"; then
                    fail "function call to '$2' failed on Server output"
                    return
                fi
                ;;
            "-f")
                if ! $2 "$CLI_OUT"; then
                    fail "function call to '$2' failed on Client output"
                    return
                fi
                ;;
            "-g")
                if ! eval "$2 '$SRV_OUT' '$CLI_OUT'"; then
                    fail "function call to '$2' failed on Server and Client output"
                    return
                fi
                ;;

            *)
                echo "Unknown test: $1" >&2
                exit 1
        esac
        shift 2
    done

    # check valgrind's results
    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SRV_CMD" && has_mem_err $SRV_OUT; then
            fail "Server has memory errors"
            return
        fi
        if is_polar "$CLI_CMD" && has_mem_err $CLI_OUT; then
            fail "Client has memory errors"
            return
        fi
    fi

    # if we're here, everything is ok
    outcome=PASS
}

# Run the current test case: start the server and if applicable the proxy, run
# the client, wait for all processes to finish or time out.
#
# Inputs:
# * $NAME: test case name
# * $CLI_CMD, $SRV_CMD, $PXY_CMD: commands to run
# * $CLI_OUT, $SRV_OUT, $PXY_OUT: files to contain client/server/proxy logs
#
# Outputs:
# * $CLI_EXIT: client return code
# * $SRV_RET: server return code
do_run_test_once() {
    # run the commands
    if [ -n "$PXY_CMD" ]; then
        printf "# %s\n%s\n" "$NAME" "$PXY_CMD" > $PXY_OUT
        $PXY_CMD >> $PXY_OUT 2>&1 &
        PXY_PID=$!
        wait_proxy_start "$PXY_PORT" "$PXY_PID"
    fi

    check_osrv_dtls
    printf '# %s\n%s\n' "$NAME" "$SRV_CMD" > $SRV_OUT
    provide_input | $SRV_CMD >> $SRV_OUT 2>&1 &
    SRV_PID=$!
    wait_server_start "$SRV_PORT" "$SRV_PID"

    printf '# %s\n%s\n' "$NAME" "$CLI_CMD" > $CLI_OUT
    eval "$CLI_CMD" >> $CLI_OUT 2>&1 &
    wait_client_done

    sleep 0.05

    # terminate the server (and the proxy)
    kill $SRV_PID
    wait $SRV_PID
    SRV_RET=$?

    if [ -n "$PXY_CMD" ]; then
        kill $PXY_PID >/dev/null 2>&1
        wait $PXY_PID
    fi
}

# Usage: run_test name [-p proxy_cmd] srv_cmd cli_cmd cli_exit [option [...]]
# Options:  -s pattern  pattern that must be present in server output
#           -c pattern  pattern that must be present in client output
#           -u pattern  lines after pattern must be unique in client output
#           -f call shell function on client output
#           -S pattern  pattern that must be absent in server output
#           -C pattern  pattern that must be absent in client output
#           -U pattern  lines after pattern must be unique in server output
#           -F call shell function on server output
#           -g call shell function on server and client output
run_test() {
    NAME="$1"
    shift 1

    if is_excluded "$NAME"; then
        SKIP_NEXT="NO"
        # There was no request to run the test, so don't record its outcome.
        return
    fi

    print_name "$NAME"

    # Do we only run numbered tests?
    if [ -n "$RUN_TEST_NUMBER" ]; then
        case ",$RUN_TEST_NUMBER," in
            *",$TESTS,"*) :;;
            *) SKIP_NEXT="YES";;
        esac
    fi

    # does this test use a proxy?
    if [ "X$1" = "X-p" ]; then
        PXY_CMD="$2"
        shift 2
    else
        PXY_CMD=""
    fi

    # get commands and client output
    SRV_CMD="$1"
    CLI_CMD="$2"
    CLI_EXPECT="$3"
    shift 3

    # Check if test uses files
    case "$SRV_CMD $CLI_CMD" in
        *data_files/*)
            requires_config_enabled MBEDTLS_FS_IO;;
    esac

    # If the client or serve requires a ciphersuite, check that it's enabled.
    maybe_requires_ciphersuite_enabled "$SRV_CMD" "$@"
    maybe_requires_ciphersuite_enabled "$CLI_CMD" "$@"

    # should we skip?
    if [ "X$SKIP_NEXT" = "XYES" ]; then
        SKIP_NEXT="NO"
        record_outcome "SKIP"
        SKIPS=$(( $SKIPS + 1 ))
        return
    fi

    analyze_test_commands "$@"

    TIMES_LEFT=2
    while [ $TIMES_LEFT -gt 0 ]; do
        TIMES_LEFT=$(( $TIMES_LEFT - 1 ))

        do_run_test_once

        check_test_failure "$@"
        case $outcome in
            PASS) break;;
            RETRY*) printf "$outcome ";;
            FAIL) return;;
        esac
    done

    # If we get this far, the test case passed.
    record_outcome "PASS"
    if [ "$PRESERVE_LOGS" -gt 0 ]; then
        mv $SRV_OUT o-srv-${TESTS}.log
        mv $CLI_OUT o-cli-${TESTS}.log
        if [ -n "$PXY_CMD" ]; then
            mv $PXY_OUT o-pxy-${TESTS}.log
        fi
    fi

    rm -f $SRV_OUT $CLI_OUT $PXY_OUT
}

cleanup() {
    rm -f $CLI_OUT $SRV_OUT $PXY_OUT $SESSION
    rm -f context_srv.txt
    rm -f context_cli.txt
    test -n "${SRV_PID:-}" && kill $SRV_PID >/dev/null 2>&1
    test -n "${PXY_PID:-}" && kill $PXY_PID >/dev/null 2>&1
    test -n "${CLI_PID:-}" && kill $CLI_PID >/dev/null 2>&1
    test -n "${DOG_PID:-}" && kill $DOG_PID >/dev/null 2>&1
    exit 1
}

#
# MAIN
#

get_options "$@"

# Optimize filters: if $FILTER and $EXCLUDE can be expressed as shell
# patterns rather than regular expressions, use a case statement instead
# of calling grep. To keep the optimizer simple, it is incomplete and only
# detects simple cases: plain substring, everything, nothing.
#
# As an exception, the character '.' is treated as an ordinary character
# if it is the only special character in the string. This is because it's
# rare to need "any one character", but needing a literal '.' is common
# (e.g. '-f "DTLS 1.2"').
need_grep=
case "$FILTER" in
    '^$') simple_filter=;;
    '.*') simple_filter='*';;
    *[][$+*?\\^{\|}]*) # Regexp special characters (other than .), we need grep
        need_grep=1;;
    *) # No regexp or shell-pattern special character
        simple_filter="*$FILTER*";;
esac
case "$EXCLUDE" in
    '^$') simple_exclude=;;
    '.*') simple_exclude='*';;
    *[][$+*?\\^{\|}]*) # Regexp special characters (other than .), we need grep
        need_grep=1;;
    *) # No regexp or shell-pattern special character
        simple_exclude="*$EXCLUDE*";;
esac
if [ -n "$need_grep" ]; then
    is_excluded () {
        ! echo "$1" | grep "$FILTER" | grep -q -v "$EXCLUDE"
    }
else
    is_excluded () {
        case "$1" in
            $simple_exclude) true;;
            $simple_filter) false;;
            *) true;;
        esac
    }
fi

# sanity checks, avoid an avalanche of errors
P_SRV_BIN="${P_SRV%%[  ]*}"
P_CLI_BIN="${P_CLI%%[  ]*}"
P_PXY_BIN="${P_PXY%%[  ]*}"
if [ ! -x "$P_SRV_BIN" ]; then
    echo "Command '$P_SRV_BIN' is not an executable file"
    exit 1
fi
if [ ! -x "$P_CLI_BIN" ]; then
    echo "Command '$P_CLI_BIN' is not an executable file"
    exit 1
fi
if [ ! -x "$P_PXY_BIN" ]; then
    echo "Command '$P_PXY_BIN' is not an executable file"
    exit 1
fi
if [ "$MEMCHECK" -gt 0 ]; then
    if which valgrind >/dev/null 2>&1; then :; else
        echo "Memcheck not possible. Valgrind not found"
        exit 1
    fi
fi
if which $OPENSSL_CMD >/dev/null 2>&1; then :; else
    echo "Command '$OPENSSL_CMD' not found"
    exit 1
fi

# used by watchdog
MAIN_PID="$$"

# We use somewhat arbitrary delays for tests:
# - how long do we wait for the server to start (when lsof not available)?
# - how long do we allow for the client to finish?
#   (not to check performance, just to avoid waiting indefinitely)
# Things are slower with valgrind, so give extra time here.
#
# Note: without lsof, there is a trade-off between the running time of this
# script and the risk of spurious errors because we didn't wait long enough.
# The watchdog delay on the other hand doesn't affect normal running time of
# the script, only the case where a client or server gets stuck.
if [ "$MEMCHECK" -gt 0 ]; then
    START_DELAY=6
    DOG_DELAY=60
else
    START_DELAY=2
    DOG_DELAY=20
fi

# some particular tests need more time:
# - for the client, we multiply the usual watchdog limit by a factor
# - for the server, we sleep for a number of seconds after the client exits
# see client_need_more_time() and server_needs_more_time()
CLI_DELAY_FACTOR=1
SRV_DELAY_SECONDS=0

# fix commands to use this port, force IPv4 while at it
# +SRV_PORT will be replaced by either $SRV_PORT or $PXY_PORT later
# Note: Using 'localhost' rather than 127.0.0.1 here is unwise, as on many
# machines that will resolve to ::1, and we don't want ipv6 here.
P_SRV="$P_SRV server_addr=127.0.0.1 server_port=$SRV_PORT"
P_CLI="$P_CLI server_addr=127.0.0.1 server_port=+SRV_PORT"
P_PXY="$P_PXY server_addr=127.0.0.1 server_port=$SRV_PORT listen_addr=127.0.0.1 listen_port=$PXY_PORT ${SEED:+"seed=$SEED"}"
O_SRV="$O_SRV -accept $SRV_PORT"
O_CLI="$O_CLI -connect 127.0.0.1:+SRV_PORT"
G_SRV="$G_SRV -p $SRV_PORT"
G_CLI="$G_CLI -p +SRV_PORT"

if [ -n "${OPENSSL_LEGACY:-}" ]; then
    O_LEGACY_SRV="$O_LEGACY_SRV -accept $SRV_PORT -dhparam data_files/dhparams.pem"
    O_LEGACY_CLI="$O_LEGACY_CLI -connect 127.0.0.1:+SRV_PORT"
fi

if [ -n "${OPENSSL_NEXT:-}" ]; then
    O_NEXT_SRV="$O_NEXT_SRV -accept $SRV_PORT"
    O_NEXT_SRV_NO_CERT="$O_NEXT_SRV_NO_CERT -accept $SRV_PORT"
    O_NEXT_CLI="$O_NEXT_CLI -connect 127.0.0.1:+SRV_PORT"
fi

if [ -n "${GNUTLS_NEXT_SERV:-}" ]; then
    G_NEXT_SRV="$G_NEXT_SRV -p $SRV_PORT"
    G_NEXT_SRV_NO_CERT="$G_NEXT_SRV_NO_CERT -p $SRV_PORT"
fi

if [ -n "${GNUTLS_NEXT_CLI:-}" ]; then
    G_NEXT_CLI="$G_NEXT_CLI -p +SRV_PORT"
fi

# Allow SHA-1, because many of our test certificates use it
P_SRV="$P_SRV allow_sha1=1"
P_CLI="$P_CLI allow_sha1=1"

# Also pick a unique name for intermediate files
SRV_OUT="srv_out.$$"
CLI_OUT="cli_out.$$"
PXY_OUT="pxy_out.$$"
SESSION="session.$$"

SKIP_NEXT="NO"

trap cleanup INT TERM HUP

# Basic test

SUB_TESTCASE_FILES=$([ -d $SUBDIRECTORY ] && (find  $SUBDIRECTORY -name \*.sh | sort ))
if [ -n "${SUB_TESTCASE_FILES}" ]
then
    for i in ${SUB_TESTCASE_FILES}
    do
        . $i
    done
fi

# Final report

echo "------------------------------------------------------------------------"

if [ $FAILS = 0 ]; then
    printf "PASSED"
else
    printf "FAILED"
fi
PASSES=$(( $TESTS - $FAILS ))
echo " ($PASSES / $TESTS tests ($SKIPS skipped))"

exit $FAILS
