#!/usr/bin/env python3
# type: ignore

"""Generate config file from local changes or command line.

    MBEDTLS_USER_CONFIG_FILE can user-provided configuration file. This script can save local
    changes of `include/mbedtls/mbedtls_config.h` as user-provided configuration file. Or generate
    user-provided configuration file according to command line input.

    To use it, export `CFLAGS="-I$PWD -DMBEDTLS_USER_CONFIG_FILE=\"<{headerfile}>\""

"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
##
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
##
# http://www.apache.org/licenses/LICENSE-2.0
##
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import re
import argparse
import itertools

from config import ConfigFile

FUNCTION_TEMPLATE = r'''
component_test_depends_curve_{with_curve}_{curve_name} () {{
    msg "Testing {with_curve} {curve} only, without MBEDTLS_USE_PSA_CRYPTO "
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set {enable_configs}
    scripts/config.py unset {disable_configs}

    make CFLAGS="-Werror -Wall -Wextra"
    make test
}}

component_test_depends_curve_{with_curve}_{curve_name}_with_psa () {{
    msg "Testing {with_curve} {curve} only, with MBEDTLS_USE_PSA_CRYPTO"
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set {enable_configs}
    scripts/config.py unset {disable_configs}

    make CFLAGS="-Werror -Wall -Wextra"
    make test
}}
ALL_COMPONENTS="$ALL_COMPONENTS test_depends_curve_{with_curve}_{curve_name}_with_psa test_depends_curve_{with_curve}_{curve_name}"
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?', default=None)
    args = parser.parse_args()
    config = ConfigFile(filename=args.input)
    curves = {k for k, v in config.settings.items()
              if (k.startswith('MBEDTLS_ECP_DP_') and k.endswith('ENABLED')) and v.active}

    def get_ecdsa_curves():
        ecdsa_curves = set()
        pattern = re.compile(r'defined\((?P<curve>MBEDTLS_ECP_DP_\w+_ENABLED)\)')
        with open('include/mbedtls/check_config.h') as f:
            found = ''
            for line in f:
                if line.startswith('#if defined(MBEDTLS_ECDSA_C)'):
                    found = line
                    continue
                if not found:
                    continue
                if found.endswith('\\\n'):
                    found += line
                    continue
                for i in pattern.finditer(found):
                    ecdsa_curves.add(i.groupdict()['curve'])
                found = ''
        return ecdsa_curves
    ecdsa_curves = get_ecdsa_curves()
    all_configs = {'MBEDTLS_ECDSA_C', 'MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED',
                   'MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED'} | curves
    always_disable = {'MBEDTLS_ECJPAKE_C',
                      'MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED'}
    for with_curve, curve in itertools.product([True, False], curves):

        if with_curve:
            if curve not in ecdsa_curves:
                enable_configs = {curve}
            else:
                enable_configs = {'MBEDTLS_ECDSA_C', 'MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED',
                                  'MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED', curve}
            disable_configs = all_configs - enable_configs

        else:
            disable_configs = {curve}
            enable_configs = all_configs - disable_configs

        disable_configs = '\n    scripts/config.py unset '.join(
            disable_configs | always_disable)
        enable_configs = '\n    scripts/config.py set '.join(enable_configs)
        curve_name = curve[len('MBEDTLS_ECP_DP_'):-len('_ENABLED')].lower()
        print(FUNCTION_TEMPLATE.format(disable_configs=disable_configs,
                                       enable_configs=enable_configs,
                                       curve_name=curve_name,
                                       curve=curve,
                                       with_curve='with' if with_curve else 'without'))

    # for k, v in curves.items():

    return 0


if __name__ == '__main__':
    sys.exit(main())
