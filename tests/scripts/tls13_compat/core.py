# tls13_compat/core.py
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

"""
Base classes and constants for generating TLSv1.3 test cases

"""

from collections import namedtuple

# define certificates configuration entry
Certificate = namedtuple("Certificate", ['cafile', 'certfile', 'keyfile'])
# define the certificate parameters for signature algorithms
CERTIFICATES = {
    'ecdsa_secp256r1_sha256': Certificate('data_files/test-ca2.crt',
                                          'data_files/ecdsa_secp256r1.crt',
                                          'data_files/ecdsa_secp256r1.key'),
    'ecdsa_secp384r1_sha384': Certificate('data_files/test-ca2.crt',
                                          'data_files/ecdsa_secp384r1.crt',
                                          'data_files/ecdsa_secp384r1.key'),
    'ecdsa_secp521r1_sha512': Certificate('data_files/test-ca2.crt',
                                          'data_files/ecdsa_secp521r1.crt',
                                          'data_files/ecdsa_secp521r1.key'),
    'rsa_pss_rsae_sha256': Certificate('data_files/test-ca_cat12.crt',
                                       'data_files/server2-sha256.crt', 'data_files/server2.key'
                                       )
}

CIPHER_SUITE_IANA_VALUE = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_AES_128_CCM_SHA256": 0x1304,
    "TLS_AES_128_CCM_8_SHA256": 0x1305
}

SIG_ALG_IANA_VALUE = {
    "ecdsa_secp256r1_sha256": 0x0403,
    "ecdsa_secp384r1_sha384": 0x0503,
    "ecdsa_secp521r1_sha512": 0x0603,
    'rsa_pss_rsae_sha256': 0x0804,
}

NAMED_GROUP_IANA_VALUE = {
    'secp256r1': 0x17,
    'secp384r1': 0x18,
    'secp521r1': 0x19,
    'x25519': 0x1d,
    'x448': 0x1e,
    # Only one finite field group to keep testing time within reasonable bounds.
    'ffdhe2048': 0x100,
}


class TLSProgram:
    """
    Base class for generate server/client command.
    """

    # pylint: disable=too-many-arguments
    def __init__(self, ciphersuite=None, signature_algorithm=None, named_group=None,
                 cert_sig_alg=None, compat_mode=True):
        self._ciphers = []
        self._sig_algs = []
        self._named_groups = []
        self._cert_sig_algs = []
        if ciphersuite:
            self.add_ciphersuites(ciphersuite)
        if named_group:
            self.add_named_groups(named_group)
        if signature_algorithm:
            self.add_signature_algorithms(signature_algorithm)
        if cert_sig_alg:
            self.add_cert_signature_algorithms(cert_sig_alg)
        self._compat_mode = compat_mode

    # add_ciphersuites should not override by sub class
    def add_ciphersuites(self, *ciphersuites):
        self._ciphers.extend(
            [cipher for cipher in ciphersuites if cipher not in self._ciphers])

    # add_signature_algorithms should not override by sub class
    def add_signature_algorithms(self, *signature_algorithms):
        self._sig_algs.extend(
            [sig_alg for sig_alg in signature_algorithms if sig_alg not in self._sig_algs])

    # add_named_groups should not override by sub class
    def add_named_groups(self, *named_groups):
        self._named_groups.extend(
            [named_group for named_group in named_groups if named_group not in self._named_groups])

    # add_cert_signature_algorithms should not override by sub class
    def add_cert_signature_algorithms(self, *signature_algorithms):
        self._cert_sig_algs.extend(
            [sig_alg for sig_alg in signature_algorithms if sig_alg not in self._cert_sig_algs])

    # pylint: disable=no-self-use
    def pre_checks(self):
        return []

    # pylint: disable=no-self-use
    def cmd(self):
        if not self._cert_sig_algs:
            self._cert_sig_algs = list(CERTIFICATES.keys())
        return self.pre_cmd()

    # pylint: disable=no-self-use
    def post_checks(self):
        return []

    # pylint: disable=no-self-use
    def pre_cmd(self):
        return ['false']


class OpenSSLBase(TLSProgram):
    """
    Generate base test commands for OpenSSL.
    """
    PROG_NAME = 'OpenSSL'

    NAMED_GROUP = {
        'secp256r1': 'P-256',
        'secp384r1': 'P-384',
        'secp521r1': 'P-521',
        'x25519': 'X25519',
        'x448': 'X448',
        'ffdhe2048': 'ffdhe2048',
    }

    def cmd(self):
        ret = super().cmd()

        if self._ciphers:
            ciphersuites = ':'.join(self._ciphers)
            ret += ["-ciphersuites {ciphersuites}".format(
                ciphersuites=ciphersuites)]

        if self._sig_algs:
            signature_algorithms = set(self._sig_algs + self._cert_sig_algs)
            signature_algorithms = ':'.join(signature_algorithms)
            ret += ["-sigalgs {signature_algorithms}".format(
                signature_algorithms=signature_algorithms)]

        if self._named_groups:
            named_groups = ':'.join(
                map(lambda named_group: self.NAMED_GROUP[named_group], self._named_groups))
            ret += ["-groups {named_groups}".format(named_groups=named_groups)]

        ret += ['-msg -tls1_3']
        if not self._compat_mode:
            ret += ['-no_middlebox']

        return ret

    def pre_checks(self):
        ret = ["requires_openssl_tls1_3"]

        # ffdh groups require at least openssl 3.0
        ffdh_groups = ['ffdhe2048']

        if any(x in ffdh_groups for x in self._named_groups):
            ret = ["requires_openssl_tls1_3_with_ffdh"]

        return ret


class OpenSSLServ(OpenSSLBase):
    """
    Generate test commands for OpenSSL server.
    """

    def cmd(self):
        ret = super().cmd()
        ret += ['-num_tickets 0 -no_resume_ephemeral -no_cache']
        return ret

    def post_checks(self):
        return ['-c "HTTP/1.0 200 ok"']

    def pre_cmd(self):
        ret = ['$O_NEXT_SRV_NO_CERT']
        for _, cert, key in map(lambda sig_alg: CERTIFICATES[sig_alg], self._cert_sig_algs):
            ret += ['-cert {cert} -key {key}'.format(cert=cert, key=key)]
        return ret


class OpenSSLCli(OpenSSLBase):
    """
    Generate test commands for OpenSSL client.
    """

    def pre_cmd(self):
        return ['$O_NEXT_CLI_NO_CERT',
                '-CAfile {cafile}'.format(cafile=CERTIFICATES[self._cert_sig_algs[0]].cafile)]


class GnuTLSBase(TLSProgram):
    """
    Generate base test commands for GnuTLS.
    """
    PROG_NAME = 'GnuTLS'

    CIPHER_SUITE = {
        'TLS_AES_256_GCM_SHA384': [
            'AES-256-GCM',
            'SHA384',
            'AEAD'],
        'TLS_AES_128_GCM_SHA256': [
            'AES-128-GCM',
            'SHA256',
            'AEAD'],
        'TLS_CHACHA20_POLY1305_SHA256': [
            'CHACHA20-POLY1305',
            'SHA256',
            'AEAD'],
        'TLS_AES_128_CCM_SHA256': [
            'AES-128-CCM',
            'SHA256',
            'AEAD'],
        'TLS_AES_128_CCM_8_SHA256': [
            'AES-128-CCM-8',
            'SHA256',
            'AEAD']}

    SIGNATURE_ALGORITHM = {
        'ecdsa_secp256r1_sha256': ['SIGN-ECDSA-SECP256R1-SHA256'],
        'ecdsa_secp521r1_sha512': ['SIGN-ECDSA-SECP521R1-SHA512'],
        'ecdsa_secp384r1_sha384': ['SIGN-ECDSA-SECP384R1-SHA384'],
        'rsa_pss_rsae_sha256': ['SIGN-RSA-PSS-RSAE-SHA256']}

    NAMED_GROUP = {
        'secp256r1': ['GROUP-SECP256R1'],
        'secp384r1': ['GROUP-SECP384R1'],
        'secp521r1': ['GROUP-SECP521R1'],
        'x25519': ['GROUP-X25519'],
        'x448': ['GROUP-X448'],
        'ffdhe2048': ['GROUP-FFDHE2048'],
    }

    def pre_checks(self):
        return ["requires_gnutls_tls1_3",
                "requires_gnutls_next_no_ticket",
                "requires_gnutls_next_disable_tls13_compat", ]

    def cmd(self):
        ret = super().cmd()

        priority_string_list = []

        def update_priority_string_list(items, map_table):
            for item in items:
                for i in map_table[item]:
                    if i not in priority_string_list:
                        yield i

        if self._ciphers:
            priority_string_list.extend(update_priority_string_list(
                self._ciphers, self.CIPHER_SUITE))
        else:
            priority_string_list.extend(['CIPHER-ALL', 'MAC-ALL'])

        if self._sig_algs:
            signature_algorithms = set(self._sig_algs + self._cert_sig_algs)
            priority_string_list.extend(update_priority_string_list(
                signature_algorithms, self.SIGNATURE_ALGORITHM))
        else:
            priority_string_list.append('SIGN-ALL')

        if self._named_groups:
            priority_string_list.extend(update_priority_string_list(
                self._named_groups, self.NAMED_GROUP))
        else:
            priority_string_list.append('GROUP-ALL')

        priority_string_list = ['NONE'] + \
            priority_string_list + ['VERS-TLS1.3']

        priority_string = ':+'.join(priority_string_list)
        priority_string += ':%NO_TICKETS'

        if not self._compat_mode:
            priority_string += [':%DISABLE_TLS13_COMPAT_MODE']

        ret += ['--priority={priority_string}'.format(
            priority_string=priority_string)]
        return ret


class GnuTLSServ(GnuTLSBase):
    """
    Generate test commands for GnuTLS server.
    """

    def pre_cmd(self):
        ret = ['$G_NEXT_SRV_NO_CERT', '--http',
               '--disable-client-cert', '--debug=4']

        for _, cert, key in map(lambda sig_alg: CERTIFICATES[sig_alg], self._cert_sig_algs):
            ret += ['--x509certfile {cert} --x509keyfile {key}'.format(
                cert=cert, key=key)]
        return ret

    def post_checks(self):
        return ['-c "HTTP/1.0 200 OK"']


class GnuTLSCli(GnuTLSBase):
    """
    Generate test commands for GnuTLS client.
    """

    def pre_cmd(self):
        return ['$G_NEXT_CLI_NO_CERT', '--debug=4', '--single-key-share',
                '--x509cafile {cafile}'.format(cafile=CERTIFICATES[self._cert_sig_algs[0]].cafile)]


class MbedTLSBase(TLSProgram):
    """
    Generate base test commands for mbedTLS.
    """
    PROG_NAME = 'mbedTLS'

    CIPHER_SUITE = {
        'TLS_AES_256_GCM_SHA384': 'TLS1-3-AES-256-GCM-SHA384',
        'TLS_AES_128_GCM_SHA256': 'TLS1-3-AES-128-GCM-SHA256',
        'TLS_CHACHA20_POLY1305_SHA256': 'TLS1-3-CHACHA20-POLY1305-SHA256',
        'TLS_AES_128_CCM_SHA256': 'TLS1-3-AES-128-CCM-SHA256',
        'TLS_AES_128_CCM_8_SHA256': 'TLS1-3-AES-128-CCM-8-SHA256'}

    def cmd(self):
        ret = super().cmd()
        ret += ['debug_level=4']

        if self._ciphers:
            ciphers = ','.join(
                map(lambda cipher: self.CIPHER_SUITE[cipher], self._ciphers))
            ret += ["force_ciphersuite={ciphers}".format(ciphers=ciphers)]

        if self._sig_algs + self._cert_sig_algs:
            ret += ['sig_algs={sig_algs}'.format(
                sig_algs=','.join(set(self._sig_algs + self._cert_sig_algs)))]

        if self._named_groups:
            named_groups = ','.join(self._named_groups)
            ret += ["groups={named_groups}".format(named_groups=named_groups)]
        return ret

    def pre_checks(self):
        ret = ['requires_config_enabled MBEDTLS_DEBUG_C',
               'requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED']

        if self._compat_mode:
            ret += ['requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE']

        if 'rsa_pss_rsae_sha256' in self._sig_algs + self._cert_sig_algs:
            ret.append(
                'requires_config_enabled MBEDTLS_X509_RSASSA_PSS_SUPPORT')

        ec_groups = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448']
        ffdh_groups = ['ffdhe2048']

        if any(x in ec_groups for x in self._named_groups):
            ret.append('requires_config_enabled PSA_WANT_ALG_ECDH')

        if any(x in ffdh_groups for x in self._named_groups):
            ret.append('requires_config_enabled PSA_WANT_ALG_FFDH')

        return ret


class MbedTLSServ(MbedTLSBase):
    """
    Generate test commands for mbedTLS server.
    """

    def cmd(self):
        ret = super().cmd()
        ret += ['tls13_kex_modes=ephemeral cookies=0 tickets=0']
        return ret

    def pre_checks(self):
        return ['requires_config_enabled MBEDTLS_SSL_SRV_C'] + super().pre_checks()

    def post_checks(self):
        check_strings = ["Protocol is TLSv1.3"]
        if self._ciphers:
            check_strings.append(
                "server hello, chosen ciphersuite: {} ( id={:04d} )".format(
                    self.CIPHER_SUITE[self._ciphers[0]],
                    CIPHER_SUITE_IANA_VALUE[self._ciphers[0]]))
        if self._sig_algs:
            check_strings.append(
                "received signature algorithm: 0x{:x}".format(
                    SIG_ALG_IANA_VALUE[self._sig_algs[0]]))

        for named_group in self._named_groups:
            check_strings += ['got named group: {named_group}({iana_value:04x})'.format(
                named_group=named_group,
                iana_value=NAMED_GROUP_IANA_VALUE[named_group])]

        check_strings.append("Certificate verification was skipped")
        return ['-s "{}"'.format(i) for i in check_strings]

    def pre_cmd(self):
        ret = ['$P_SRV']
        for _, cert, key in map(lambda sig_alg: CERTIFICATES[sig_alg], self._cert_sig_algs):
            ret += ['crt_file={cert} key_file={key}'.format(
                cert=cert, key=key)]
        return ret


class MbedTLSCli(MbedTLSBase):
    """
    Generate test commands for mbedTLS client.
    """

    def pre_cmd(self):
        return ['$P_CLI',
                'ca_file={cafile}'.format(cafile=CERTIFICATES[self._cert_sig_algs[0]].cafile)]

    def pre_checks(self):
        return ['requires_config_enabled MBEDTLS_SSL_CLI_C'] + super().pre_checks()

    def post_checks(self):
        check_strings = ["Protocol is TLSv1.3"]
        if self._ciphers:
            check_strings.append(
                "server hello, chosen ciphersuite: ( {:04x} ) - {}".format(
                    CIPHER_SUITE_IANA_VALUE[self._ciphers[0]],
                    self.CIPHER_SUITE[self._ciphers[0]]))
        if self._sig_algs:
            check_strings.append(
                "Certificate Verify: Signature algorithm ( {:04x} )".format(
                    SIG_ALG_IANA_VALUE[self._sig_algs[0]]))

        for named_group in self._named_groups:
            check_strings += ['NamedGroup: {named_group} ( {iana_value:x} )'.format(
                named_group=named_group,
                iana_value=NAMED_GROUP_IANA_VALUE[named_group])]

        check_strings.append("Verifying peer X.509 certificate... ok")
        return ['-c "{}"'.format(i) for i in check_strings]
