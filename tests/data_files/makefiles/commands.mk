

################################################################
#### Generate certificates from existing keys
################################################################

test_ca_crt = test-ca.crt
test_ca_key_file_rsa = test-ca.key
test_ca_pwd_rsa = PolarSSLTest
test_ca_config_file = test-ca.opensslconf

$(test_ca_key_file_rsa):
	$(OPENSSL) genrsa -aes-128-cbc -passout pass:$(test_ca_pwd_rsa) -out $@ 2048
all_final += $(test_ca_key_file_rsa)

test-ca.req.sha256: $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$(test_ca_key_file_rsa) password=$(test_ca_pwd_rsa) subject_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" md=SHA256
all_intermediate += test-ca.req.sha256

parse_input/test-ca.crt test-ca.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 request_file=test-ca.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA1 version=3 output_file=$@
all_final += test-ca.crt

parse_input/test-ca.crt.der: test-ca.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

test-ca.key.der: $(test_ca_key_file_rsa)
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER -passin "pass:$(test_ca_pwd_rsa)"
all_final += test-ca.key.der

test-ca-sha1.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 request_file=test-ca.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA1 version=3 output_file=$@
all_final += test-ca-sha1.crt

test-ca-sha1.crt.der: test-ca-sha1.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += test-ca-sha1.crt.der

test-ca-sha256.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 request_file=test-ca.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA256 version=3 output_file=$@
all_final += test-ca-sha256.crt

test-ca-sha256.crt.der: test-ca-sha256.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += test-ca-sha256.crt.der

test-ca_utf8.crt: $(test_ca_key_file_rsa)
	$(OPENSSL) req -x509 -new -nodes -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 3 -config $(test_ca_config_file) -sha1 -days 3653 -utf8 -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_final += test-ca_utf8.crt

test-ca_printable.crt: $(test_ca_key_file_rsa)
	$(OPENSSL) req -x509 -new -nodes -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 3 -config $(test_ca_config_file) -sha1 -days 3653 -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_final += test-ca_printable.crt

test-ca_uppercase.crt: $(test_ca_key_file_rsa)
	$(OPENSSL) req -x509 -new -nodes -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 3 -config $(test_ca_config_file) -sha1 -days 3653 -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_final += test-ca_uppercase.crt

test_ca_key_file_rsa_alt = test-ca-alt.key

cert_example_multi.csr: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=www.example.com" -set_serial 17 -config $(test_ca_config_file) -extensions dns_alt_names -days 3650 -key rsa_pkcs1_1024_clear.pem -out $@

parse_input/cert_example_multi.crt cert_example_multi.crt: cert_example_multi.csr
	$(OPENSSL) x509 -req -CA $(test_ca_crt) -CAkey $(test_ca_key_file_rsa) \
		-extfile $(test_ca_config_file) -extensions dns_alt_names \
		-passin "pass:$(test_ca_pwd_rsa)" -set_serial 17 -days 3653 -sha256 \
		-in $< > $@

parse_input/test_csr_v3_keyUsage.csr.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) req -new -subj '/CN=etcd' -config $(test_ca_config_file) -key rsa_pkcs1_1024_clear.pem -outform DER -out $@ -reqexts csr_ext_v3_keyUsage
parse_input/test_csr_v3_subjectAltName.csr.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) req -new -subj '/CN=etcd' -config $(test_ca_config_file) -key rsa_pkcs1_1024_clear.pem -outform DER -out $@ -reqexts csr_ext_v3_subjectAltName
parse_input/test_csr_v3_nsCertType.csr.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) req -new -subj '/CN=etcd' -config $(test_ca_config_file) -key rsa_pkcs1_1024_clear.pem -outform DER -out $@ -reqexts csr_ext_v3_nsCertType
parse_input/test_csr_v3_all.csr.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) req -new -subj '/CN=etcd' -config $(test_ca_config_file) -key rsa_pkcs1_1024_clear.pem -outform DER -out $@ -reqexts csr_ext_v3_all
parse_input/test_csr_v3_all_malformed_extensions_sequence_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/300B0603551D0F040403/200B0603551D0F040403/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_id_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/0603551D0F0404030201/0703551D0F0404030201/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_data_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/040403020102302F0603/050403020102302F0603/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_data_len1.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/040403020102302F0603/040503020102302F0603/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_data_len2.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/040403020102302F0603/040303020102302F0603/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_key_usage_bitstream_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/03020102302F0603551D/04020102302F0603551D/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_subject_alt_name_sequence_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/3026A02406082B060105/4026A02406082B060105/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_ns_cert_bitstream_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/03020780300D06092A86/04020780300D06092A86/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_duplicated_extension.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/551D11/551D0F/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_extension_type_oid.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/551D11/551DFF/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_sequence_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/306006092A864886F70D/406006092A864886F70D/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_id_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/06092A864886F70D0109/07092A864886F70D0109/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_extension_request.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/2A864886F70D01090E/2A864886F70D01090F/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_extension_request_set_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/31533051300B0603551D/32533051300B0603551D/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_extension_request_sequence_tag.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/3051300B0603551D0F04/3151300B0603551D0F04/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_len1.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/306006092A864886F70D/306106092A864886F70D/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_len2.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/306006092A864886F70D/305906092A864886F70D/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_extension_request_sequence_len1.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/3051300B0603551D0F04/3052300B0603551D0F04/" | xxd -r -p ) > $@
parse_input/test_csr_v3_all_malformed_attributes_extension_request_sequence_len2.csr.der: parse_input/test_csr_v3_all.csr.der
	(hexdump -ve '1/1 "%.2X"' $< | sed "s/3051300B0603551D0F04/3050300B0603551D0F04/" | xxd -r -p ) > $@

parse_input/test_cert_rfc822name.crt.der: cert_example_multi.csr
	$(OPENSSL) x509 -req -CA $(test_ca_crt) -CAkey $(test_ca_key_file_rsa) -extfile $(test_ca_config_file) -outform DER -extensions rfc822name_names -passin "pass:$(test_ca_pwd_rsa)" -set_serial 17 -days 3653 -sha256 -in $< > $@

$(test_ca_key_file_rsa_alt):test-ca.opensslconf
	$(OPENSSL) genrsa -out $@ 2048
test-ca-alt.csr: $(test_ca_key_file_rsa_alt) $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key $(test_ca_key_file_rsa_alt) -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_intermediate += test-ca-alt.csr
test-ca-alt.crt: $(test_ca_key_file_rsa_alt) $(test_ca_config_file) test-ca-alt.csr
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -key $(test_ca_key_file_rsa_alt) -set_serial 0 -days 3653 -sha256 -in test-ca-alt.csr -out $@
all_final += test-ca-alt.crt
test-ca-alt-good.crt: test-ca-alt.crt test-ca-sha256.crt
	cat test-ca-alt.crt test-ca-sha256.crt > $@
all_final += test-ca-alt-good.crt
test-ca-good-alt.crt: test-ca-alt.crt test-ca-sha256.crt
	cat test-ca-sha256.crt test-ca-alt.crt > $@
all_final += test-ca-good-alt.crt

test_ca_crt_file_ec = test-ca2.crt
test_ca_key_file_ec = test-ca2.key

test-ca2.req.sha256: $(test_ca_key_file_ec)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$(test_ca_key_file_ec) subject_name="C=NL,O=PolarSSL,CN=Polarssl Test EC CA" md=SHA256
all_intermediate += test-ca2.req.sha256

test-ca2.crt: $(test_ca_key_file_ec) test-ca2.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=13926223505202072808 request_file=test-ca2.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=Polarssl Test EC CA" issuer_key=$(test_ca_key_file_ec) not_before=20190210144400 not_after=20290210144400 md=SHA256 version=3 output_file=$@
all_final += test-ca2.crt

test-ca2-future.crt: $(test_ca_key_file_ec) test-ca2.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=13926223505202072808 request_file=test-ca2.req.sha256 selfsign=1 \
		issuer_name="C=NL,O=PolarSSL,CN=Polarssl Test EC CA" issuer_key=$(test_ca_key_file_ec) \
		not_before=20290210144400 not_after=20390210144400 md=SHA256 version=3 output_file=$@
all_intermediate += test-ca2-future.crt

test_ca_ec_cat := # files that concatenate different crt
test-ca2_cat-future-invalid.crt: test-ca2-future.crt server6.crt
test_ca_ec_cat += test-ca2_cat-future-invalid.crt
test-ca2_cat-future-present.crt: test-ca2-future.crt test-ca2.crt
test_ca_ec_cat += test-ca2_cat-future-present.crt
test-ca2_cat-present-future.crt: test-ca2.crt test-ca2-future.crt
test_ca_ec_cat += test-ca2_cat-present-future.crt
test-ca2_cat-present-past.crt: test-ca2.crt test-ca2-expired.crt
test_ca_ec_cat += test-ca2_cat-present-past.crt
test-ca2_cat-past-invalid.crt: test-ca2-expired.crt server6.crt
test_ca_ec_cat += test-ca2_cat-past-invalid.crt
test-ca2_cat-past-present.crt: test-ca2-expired.crt test-ca2.crt
test_ca_ec_cat += test-ca2_cat-past-present.crt
$(test_ca_ec_cat):
	cat $^ > $@
all_final += $(test_ca_ec_cat)

parse_input/test-ca-any_policy.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@

parse_input/test-ca-any_policy_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@

parse_input/test-ca-any_policy_with_qualifier.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_qualifier_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@

parse_input/test-ca-any_policy_with_qualifier_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_qualifier_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@

parse_input/test-ca-multi_policy.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_multi_policy_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@

parse_input/test-ca-multi_policy_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_multi_policy_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@

parse_input/test-ca-unsupported_policy.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_unsupported_policy_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@

parse_input/test-ca-unsupported_policy_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_unsupported_policy_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@

test-ca.req_ec.sha256: $(test_ca_key_file_ec)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$(test_ca_key_file_ec) subject_name="C=NL, O=PolarSSL, CN=Polarssl Test EC CA" md=SHA256
all_intermediate += test-ca.req_ec.sha256

test-ca2.crt.der: $(test_ca_crt_file_ec)
	$(OPENSSL) x509 -in $(test_ca_crt_file_ec) -out $@ -inform PEM -outform DER
all_final += test-ca2.crt.der

test-ca2.key.der: $(test_ca_key_file_ec)
	$(OPENSSL) pkey -in $(test_ca_key_file_ec) -out $@ -inform PEM -outform DER
all_final += test-ca2.key.der

test_ca_crt_cat12 = test-ca_cat12.crt
$(test_ca_crt_cat12): $(test_ca_crt) $(test_ca_crt_file_ec)
	cat $(test_ca_crt) $(test_ca_crt_file_ec) > $@
all_final += $(test_ca_crt_cat12)

test_ca_crt_cat21 = test-ca_cat21.crt
$(test_ca_crt_cat21): $(test_ca_crt) $(test_ca_crt_file_ec)
	cat $(test_ca_crt_file_ec) $(test_ca_crt) > $@
all_final += $(test_ca_crt_cat21)

test-int-ca.csr: test-int-ca.key $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key test-int-ca.key -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test Intermediate CA" -out $@

test-int-ca2.csr: test-int-ca2.key $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key test-int-ca2.key \
		-subj "/C=NL/O=PolarSSL/CN=PolarSSL Test Intermediate EC CA" -out $@

test-int-ca3.csr: test-int-ca3.key $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key test-int-ca3.key \
		-subj "/C=UK/O=mbed TLS/CN=mbed TLS Test intermediate CA 3" -out $@

all_intermediate += test-int-ca.csr test-int-ca2.csr test-int-ca3.csr

test-int-ca.crt: $(test_ca_crt_file_ec) $(test_ca_key_file_ec) $(test_ca_config_file) test-int-ca.csr
	$(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions v3_ca \
		-CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
		-set_serial 14 -days 3653 -sha256 -in test-int-ca.csr -out $@

test-int-ca2.crt: $(test_ca_key_file_rsa) $(test_ca_crt) $(test_ca_config_file) test-int-ca2.csr
	$(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions v3_ca -CA $(test_ca_crt) \
		-CAkey $(test_ca_key_file_rsa) -set_serial 15 -days 3653 -sha256 -in test-int-ca2.csr \
		-passin "pass:$(test_ca_pwd_rsa)" -out $@

# Note: This requests openssl version >= 3.x.xx
test-int-ca3.crt: test-int-ca2.crt test-int-ca2.key $(test_ca_config_file) test-int-ca3.csr
	$(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions no_subj_auth_id \
		-CA test-int-ca2.crt -CAkey test-int-ca2.key -set_serial 77 -days 3653 \
			-sha256 -in test-int-ca3.csr -out $@

test-int-ca-exp.crt: $(test_ca_crt_file_ec) $(test_ca_key_file_ec) $(test_ca_config_file) test-int-ca.csr
	$(FAKETIME) -f -3653d $(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions v3_ca -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) -set_serial 14 -days 3653 -sha256 -in test-int-ca.csr -out $@

all_final += test-int-ca-exp.crt test-int-ca.crt test-int-ca2.crt test-int-ca3.crt

enco-cert-utf8str.pem: rsa_pkcs1_1024_clear.pem
	$(MBEDTLS_CERT_WRITE) subject_key=rsa_pkcs1_1024_clear.pem subject_name="CN=dw.yonan.net" issuer_crt=enco-ca-prstr.pem issuer_key=rsa_pkcs1_1024_clear.pem not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@

parse_input/crl-idp.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_config_file) -name test_ca -md sha256 -crldays 3653 -crlexts crl_ext_idp -out $@
parse_input/crl-idpnc.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_config_file) -name test_ca -md sha256 -crldays 3653 -crlexts crl_ext_idp_nc -out $@

cli_crt_key_file_rsa = cli-rsa.key
cli_crt_extensions_file = cli.opensslconf

cli-rsa.csr: $(cli_crt_key_file_rsa)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Client 2" md=SHA1
all_intermediate += cli-rsa.csr

cli-rsa-sha1.crt: cli-rsa.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=4 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@

cli-rsa-sha256.crt: cli-rsa.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=4 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += cli-rsa-sha256.crt

cli-rsa-sha256.crt.der: cli-rsa-sha256.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += cli-rsa-sha256.crt.der

parse_input/cli-rsa-sha256-badalg.crt.der: cli-rsa-sha256.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/06092A864886F70D01010B0500/06092A864886F70D01010B0900/2" | xxd -r -p > $@

cli-rsa.key.der: $(cli_crt_key_file_rsa)
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += cli-rsa.key.der

test_ca_int_rsa1 = test-int-ca.crt
test_ca_int_ec = test-int-ca2.crt
test_ca_int_key_file_ec = test-int-ca2.key

# server7*

server7.csr: server7.key
	$(OPENSSL) req -new -key server7.key -subj "/C=NL/O=PolarSSL/CN=localhost" -out $@
all_intermediate += server7.csr

server7.crt: server7.csr $(test_ca_int_rsa1)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa \
		-CA $(test_ca_int_rsa1) -CAkey test-int-ca.key \
		-set_serial 16 -days 3653 -sha256 -in server7.csr > $@
all_final += server7.crt

server7-expired.crt: server7.csr $(test_ca_int_rsa1)
	$(FAKETIME) -f -3653d $(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA $(test_ca_int_rsa1) -CAkey test-int-ca.key -set_serial 16 -days 3653 -sha256 -in server7.csr | cat - $(test_ca_int_rsa1) > $@
all_final += server7-expired.crt

server7-future.crt: server7.csr $(test_ca_int_rsa1)
	$(FAKETIME) -f +3653d $(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA $(test_ca_int_rsa1) -CAkey test-int-ca.key -set_serial 16 -days 3653 -sha256 -in server7.csr | cat - $(test_ca_int_rsa1) > $@
all_final += server7-future.crt

server7-badsign.crt: server7.crt $(test_ca_int_rsa1)
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; cat $(test_ca_int_rsa1); } > $@
all_final += server7-badsign.crt

parse_input/server7_int-ca.crt server7_int-ca.crt: server7.crt $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_rsa1) > $@
all_final += server7_int-ca.crt

parse_input/server7_pem_space.crt: server7.crt $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_rsa1) | sed '4s/\(.\)$$/ \1/' > $@

parse_input/server7_all_space.crt: server7.crt $(test_ca_int_rsa1)
	{ cat server7.crt | sed '4s/\(.\)$$/ \1/'; cat test-int-ca.crt | sed '4s/\(.\)$$/ \1/'; } > $@

parse_input/server7_trailing_space.crt: server7.crt $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_rsa1) | sed 's/\(.\)$$/\1 /' > $@

server7_int-ca_ca2.crt: server7.crt $(test_ca_int_rsa1) $(test_ca_crt_file_ec)
	cat server7.crt $(test_ca_int_rsa1) $(test_ca_crt_file_ec) > $@
all_final += server7_int-ca_ca2.crt

server7_int-ca-exp.crt: server7.crt test-int-ca-exp.crt
	cat server7.crt test-int-ca-exp.crt > $@
all_final += server7_int-ca-exp.crt

server7_spurious_int-ca.crt: server7.crt $(test_ca_int_ec) $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_ec) $(test_ca_int_rsa1) > $@
all_final += server7_spurious_int-ca.crt

# server8*

server8.crt: server8.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="C=NL, O=PolarSSL, CN=localhost" serial=17 \
		issuer_crt=$(test_ca_int_ec) issuer_key=$(test_ca_int_key_file_ec) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=3 output_file=$@
all_final += server8.crt

server8_int-ca2.crt: server8.crt $(test_ca_int_ec)
	cat $^ > $@
all_final += server8_int-ca2.crt

cli2.req.sha256: cli2.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Test Client 2" md=SHA256

all_final += server1.req.sha1
cli2.crt: cli2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=cli2.req.sha256 serial=13 selfsign=0 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test EC CA" issuer_key=$(test_ca_key_file_ec) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA256 version=3 output_file=$@
all_final += cli2.crt

cli2.crt.der: cli2.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += cli2.crt.der

cli2.key.der: cli2.key
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += cli2.key.der

server5_pwd_ec = PolarSSLTest

server5.crt.der: server5.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += server5.crt.der

server5.key.der: server5.key
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += server5.key.der

server5.key.enc: server5.key
	$(OPENSSL) ec -aes256 -in $< -out $@ -passout "pass:$(server5_pwd_ec)"
all_final += server5.key.enc

server5-ss-expired.crt: server5.key
	$(FAKETIME) -f -3653d $(OPENSSL) req -x509 -new -subj "/C=UK/O=mbed TLS/OU=testsuite/CN=localhost" -days 3653 -sha256 -key $< -out $@
all_final += server5-ss-expired.crt

# try to forge a copy of test-int-ca3 with different key
server5-ss-forgeca.crt: server5.key
	$(FAKETIME) '2015-09-01 14:08:43' $(OPENSSL) req -x509 -new -subj "/C=UK/O=mbed TLS/CN=mbed TLS Test intermediate CA 3" -set_serial 77 -config $(test_ca_config_file) -extensions noext_ca -days 3650 -sha256 -key $< -out $@
all_final += server5-ss-forgeca.crt

parse_input/server5-othername.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS othername SAN" -set_serial 77 -config $(test_ca_config_file) -extensions othername_san -days 3650 -sha256 -key $< -out $@

parse_input/server5-nonprintable_othername.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS non-printable othername SAN" -set_serial 77 -config $(test_ca_config_file) -extensions nonprintable_othername_san -days 3650 -sha256 -key $< -out $@

parse_input/server5-unsupported_othername.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS unsupported othername SAN" -set_serial 77 -config $(test_ca_config_file) -extensions unsupported_othername_san -days 3650 -sha256 -key $< -out $@

parse_input/server5-fan.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS FAN" -set_serial 77 -config $(test_ca_config_file) -extensions fan_cert -days 3650 -sha256 -key server5.key -out $@

server5-tricky-ip-san.crt.der: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS Tricky IP SAN" -set_serial 77 -config $(test_ca_config_file) -extensions tricky_ip_san -days 3650 -sha256 -key server5.key -outform der -out $@

# malformed IP length
server5-tricky-ip-san-malformed-len.crt.der: server5-tricky-ip-san.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/87046162636487106162/87056162636487106162/" | xxd -r -p > $@

parse_input/server5-directoryname.crt.der: server5.key
	$(OPENSSL) req -x509 -outform der -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS directoryName SAN" -set_serial 77 -config $(test_ca_config_file) -extensions directory_name_san -days 3650 -sha256 -key server5.key -out $@

parse_input/server5-two-directorynames.crt.der: server5.key
	$(OPENSSL) req -x509 -outform der -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS directoryName SAN" -set_serial 77 -config $(test_ca_config_file) -extensions two_directorynames -days 3650 -sha256 -key server5.key -out $@

server5-der0.crt: server5.crt.der
	cp $< $@
server5-der1a.crt: server5.crt.der
	cp $< $@
	echo '00' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der1b.crt: server5.crt.der
	cp $< $@
	echo 'c1' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der2.crt: server5.crt.der
	cp $< $@
	echo 'b90a' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der4.crt: server5.crt.der
	cp $< $@
	echo 'a710945f' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der8.crt: server5.crt.der
	cp $< $@
	echo 'a4a7ff27267aaa0f' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der9.crt: server5.crt.der
	cp $< $@
	echo 'cff8303376ffa47a29' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
all_final += server5-der0.crt server5-der1b.crt server5-der4.crt \
			 server5-der9.crt server5-der1a.crt server5-der2.crt \
			 server5-der8.crt

# directoryname sequence tag malformed
parse_input/server5-directoryname-seq-malformed.crt.der: server5-two-directorynames.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/62A4473045310B/62A4473145310B/" | xxd -r -p > $@

# Second directoryname OID length malformed 03 -> 15
parse_input/server5-second-directoryname-oid-malformed.crt.der: server5-two-directorynames.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/0355040A0C0A4D414C464F524D5F4D45/1555040A0C0A4D414C464F524D5F4D45/" | xxd -r -p > $@

all_final += server5-tricky-ip-san.crt

parse_input/rsa_single_san_uri.crt.der: rsa_single_san_uri.key
	$(OPENSSL) req -x509 -outform der -nodes -days 7300 -newkey rsa:2048 -key $< -out $@ -addext "subjectAltName = URI:urn:example.com:5ff40f78-9210-494f-8206-c2c082f0609c" -extensions 'v3_req' -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS URI SAN"

parse_input/rsa_multiple_san_uri.crt.der: rsa_multiple_san_uri.key
	$(OPENSSL) req -x509 -outform der -nodes -days 7300 -newkey rsa:2048 -key $< -out $@ -addext "subjectAltName = URI:urn:example.com:5ff40f78-9210-494f-8206-c2c082f0609c, URI:urn:example.com:5ff40f78-9210-494f-8206-abcde1234567" -extensions 'v3_req' -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS URI SAN"

test-int-ca3-badsign.crt: test-int-ca3.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += test-int-ca3-badsign.crt

# server10*

server10.crt: server10.key test-int-ca3.crt test-int-ca3.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="CN=localhost" serial=75 \
		issuer_crt=test-int-ca3.crt issuer_key=test-int-ca3.key \
		subject_identifier=0 authority_identifier=0 \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=3 output_file=$@
all_final += server10.crt
server10-badsign.crt: server10.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += server10-badsign.crt
server10-bs_int3.pem: server10-badsign.crt test-int-ca3.crt
	cat server10-badsign.crt test-int-ca3.crt > $@
all_final += server10-bs_int3.pem
server10_int3-bs.pem: server10.crt test-int-ca3-badsign.crt
	cat server10.crt test-int-ca3-badsign.crt > $@
all_final += server10_int3-bs.pem
server10_int3_int-ca2.crt: server10.crt test-int-ca3.crt $(test_ca_int_ec)
	cat $^ > $@
all_final += server10_int3_int-ca2.crt
server10_int3_int-ca2_ca.crt: server10.crt test-int-ca3.crt $(test_ca_int_ec) $(test_ca_crt)
	cat $^ > $@
all_final += server10_int3_int-ca2_ca.crt
server10_int3_spurious_int-ca2.crt: server10.crt test-int-ca3.crt $(test_ca_int_rsa1) $(test_ca_int_ec)
	cat $^ > $@
all_final += server10_int3_spurious_int-ca2.crt

rsa_pkcs1_2048_public.pem: server8.key
	$(OPENSSL)  rsa -in $< -outform PEM -RSAPublicKey_out -out $@
all_final += rsa_pkcs1_2048_public.pem

rsa_pkcs1_2048_public.der: rsa_pkcs1_2048_public.pem
	$(OPENSSL) rsa -RSAPublicKey_in -in $< -outform DER -RSAPublicKey_out -out $@
all_final += rsa_pkcs1_2048_public.der

rsa_pkcs8_2048_public.pem: server8.key
	$(OPENSSL)  rsa -in $< -outform PEM -pubout -out $@
all_final += rsa_pkcs8_2048_public.pem

rsa_pkcs8_2048_public.der: rsa_pkcs8_2048_public.pem
	$(OPENSSL) rsa -pubin -in $< -outform DER -pubout -out $@
all_final += rsa_pkcs8_2048_public.der

# Generate crl_cat_*.pem
# - crt_cat_*.pem: (1+2) concatenations in various orders:
#     ec = crl-ec-sha256.pem, ecfut = crl-future.pem
#     rsa = crl.pem, rsabadpem = same with pem error, rsaexp = crl_expired.pem

crl_cat_ec-rsa.pem:crl-ec-sha256.pem crl.pem
	cat $^ > $@

crl_cat_rsa-ec.pem:crl.pem crl-ec-sha256.pem
	cat $^ > $@

all_final += crl_cat_ec-rsa.pem crl_cat_rsa-ec.pem

authorityKeyId_subjectKeyId.crt.der:
	$(OPENSSL) req -x509 -nodes -days 7300 -key server2.key -outform DER -out $@ -config authorityKeyId_subjectKeyId.conf -extensions 'v3_req' -set_serial 593828494303792449134898749208168108403991951034

authorityKeyId_no_keyid.crt.der:
	$(OPENSSL) req -x509 -nodes -days 7300 -key server2.key -outform DER -out $@ -config authorityKeyId_subjectKeyId.conf -extensions 'v3_req_authorityKeyId_no_keyid' -set_serial 593828494303792449134898749208168108403991951034

authorityKeyId_no_issuer.crt.der:
	$(OPENSSL) req -x509 -nodes -days 7300 -key server2.key -outform DER -out $@ -config authorityKeyId_subjectKeyId.conf -extensions 'v3_req_authorityKeyId_no_issuer'

authorityKeyId_no_authorityKeyId.crt.der:
	$(OPENSSL) req -x509 -nodes -days 7300 -key server2.key -outform DER -out $@ -config authorityKeyId_subjectKeyId.conf -extensions 'v3_req_no_authorityKeyId'

authorityKeyId_subjectKeyId_tag_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/0414A505E864B8DCDF600F50124D60A864AF4D8B4393/0114A505E864B8DCDF600F50124D60A864AF4D8B4393/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_tag_len_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/0414A505E864B8DCDF600F50124D60A864AF4D8B4393/0413A505E864B8DCDF600F50124D60A864AF4D8B4393/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_length_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/306D8014A505E864B8DC/306C8014A505E864B8DC/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_sequence_tag_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/6F306D8014A505E864B8/6F006D8014A505E864B8/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_keyid_tag_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/306D8014A505E864B8DC/306D0014A505E864B8DC/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_keyid_tag_len_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/306D8014A505E864B8DC/306D80FFA505E864B8DC/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_issuer_tag1_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/A13FA43D303B310B3009/003FA43D303B310B3009/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_issuer_tag2_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/A43D303B310B30090603/003D303B310B30090603/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_sn_tag_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/8214680430CD074DE63F/8114680430CD074DE63F/" | xxd -r -p > $@

authorityKeyId_subjectKeyId_sn_len_malformed.crt.der: authorityKeyId_subjectKeyId.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/8214680430CD074DE63F/8213680430CD074DE63F/" | xxd -r -p > $@

################################################################
#### Generate various RSA keys
################################################################

### Password used for PKCS1-encoded encrypted RSA keys
keys_rsa_basic_pwd = testkey

### Password used for PKCS8-encoded encrypted RSA keys
keys_rsa_pkcs8_pwd = PolarSSLTest

### Basic 1024-, 2048- and 4096-bit unencrypted RSA keys from which
### all other encrypted RSA keys are derived.
rsa_pkcs1_1024_clear.pem:
	$(OPENSSL) genrsa -out $@ 1024
all_final += rsa_pkcs1_1024_clear.pem
rsa_pkcs1_2048_clear.pem:
	$(OPENSSL) genrsa -out $@ 2048
all_final += rsa_pkcs1_2048_clear.pem
rsa_pkcs1_4096_clear.pem:
	$(OPENSSL) genrsa -out $@ 4096
all_final += rsa_pkcs1_4096_clear.pem

###
### PKCS1-encoded, encrypted RSA keys
###

### 1024-bit
rsa_pkcs1_1024_des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_des.pem
rsa_pkcs1_1024_3des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_3des.pem
rsa_pkcs1_1024_aes128.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_aes128.pem
rsa_pkcs1_1024_aes192.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_aes192.pem
rsa_pkcs1_1024_aes256.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_aes256.pem
keys_rsa_enc_basic_1024: rsa_pkcs1_1024_des.pem rsa_pkcs1_1024_3des.pem rsa_pkcs1_1024_aes128.pem rsa_pkcs1_1024_aes192.pem rsa_pkcs1_1024_aes256.pem

# 2048-bit
rsa_pkcs1_2048_des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_des.pem
rsa_pkcs1_2048_3des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_3des.pem
rsa_pkcs1_2048_aes128.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_aes128.pem
rsa_pkcs1_2048_aes192.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_aes192.pem
rsa_pkcs1_2048_aes256.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_aes256.pem
keys_rsa_enc_basic_2048: rsa_pkcs1_2048_des.pem rsa_pkcs1_2048_3des.pem rsa_pkcs1_2048_aes128.pem rsa_pkcs1_2048_aes192.pem rsa_pkcs1_2048_aes256.pem

# 4096-bit
rsa_pkcs1_4096_des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_des.pem
rsa_pkcs1_4096_3des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_3des.pem
rsa_pkcs1_4096_aes128.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_aes128.pem
rsa_pkcs1_4096_aes192.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_aes192.pem
rsa_pkcs1_4096_aes256.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_aes256.pem
keys_rsa_enc_basic_4096: rsa_pkcs1_4096_des.pem rsa_pkcs1_4096_3des.pem rsa_pkcs1_4096_aes128.pem rsa_pkcs1_4096_aes192.pem rsa_pkcs1_4096_aes256.pem

###
### PKCS8-v1 encoded, encrypted RSA keys
###

### 1024-bit
rsa_pkcs8_pbe_sha1_1024_3des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_1024_3des.der
rsa_pkcs8_pbe_sha1_1024_3des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_1024_3des.pem
keys_rsa_enc_pkcs8_v1_1024_3des: rsa_pkcs8_pbe_sha1_1024_3des.pem rsa_pkcs8_pbe_sha1_1024_3des.der

rsa_pkcs8_pbe_sha1_1024_2des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_1024_2des.der
rsa_pkcs8_pbe_sha1_1024_2des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_1024_2des.pem
keys_rsa_enc_pkcs8_v1_1024_2des: rsa_pkcs8_pbe_sha1_1024_2des.pem rsa_pkcs8_pbe_sha1_1024_2des.der

keys_rsa_enc_pkcs8_v1_1024: keys_rsa_enc_pkcs8_v1_1024_3des keys_rsa_enc_pkcs8_v1_1024_2des

### 2048-bit
rsa_pkcs8_pbe_sha1_2048_3des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_2048_3des.der
rsa_pkcs8_pbe_sha1_2048_3des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_2048_3des.pem
keys_rsa_enc_pkcs8_v1_2048_3des: rsa_pkcs8_pbe_sha1_2048_3des.pem rsa_pkcs8_pbe_sha1_2048_3des.der

rsa_pkcs8_pbe_sha1_2048_2des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_2048_2des.der
rsa_pkcs8_pbe_sha1_2048_2des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_2048_2des.pem
keys_rsa_enc_pkcs8_v1_2048_2des: rsa_pkcs8_pbe_sha1_2048_2des.pem rsa_pkcs8_pbe_sha1_2048_2des.der

keys_rsa_enc_pkcs8_v1_2048: keys_rsa_enc_pkcs8_v1_2048_3des keys_rsa_enc_pkcs8_v1_2048_2des

### 4096-bit
rsa_pkcs8_pbe_sha1_4096_3des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_4096_3des.der
rsa_pkcs8_pbe_sha1_4096_3des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_4096_3des.pem
keys_rsa_enc_pkcs8_v1_4096_3des: rsa_pkcs8_pbe_sha1_4096_3des.pem rsa_pkcs8_pbe_sha1_4096_3des.der

rsa_pkcs8_pbe_sha1_4096_2des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_4096_2des.der
rsa_pkcs8_pbe_sha1_4096_2des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_4096_2des.pem
keys_rsa_enc_pkcs8_v1_4096_2des: rsa_pkcs8_pbe_sha1_4096_2des.pem rsa_pkcs8_pbe_sha1_4096_2des.der

keys_rsa_enc_pkcs8_v1_4096: keys_rsa_enc_pkcs8_v1_4096_3des keys_rsa_enc_pkcs8_v1_4096_2des

###
### PKCS8-v2 encoded, encrypted RSA keys, no PRF specified (default for OpenSSL1.0: hmacWithSHA1)
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem
keys_rsa_enc_pkcs8_v2_1024_3des: rsa_pkcs8_pbes2_pbkdf2_1024_3des.der rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des.der
rsa_pkcs8_pbes2_pbkdf2_1024_des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des.pem
keys_rsa_enc_pkcs8_v2_1024_des: rsa_pkcs8_pbes2_pbkdf2_1024_des.der rsa_pkcs8_pbes2_pbkdf2_1024_des.pem

keys_rsa_enc_pkcs8_v2_1024: keys_rsa_enc_pkcs8_v2_1024_3des keys_rsa_enc_pkcs8_v2_1024_des

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des.pem
keys_rsa_enc_pkcs8_v2_2048_3des: rsa_pkcs8_pbes2_pbkdf2_2048_3des.der rsa_pkcs8_pbes2_pbkdf2_2048_3des.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des.der
rsa_pkcs8_pbes2_pbkdf2_2048_des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des.pem
keys_rsa_enc_pkcs8_v2_2048_des: rsa_pkcs8_pbes2_pbkdf2_2048_des.der rsa_pkcs8_pbes2_pbkdf2_2048_des.pem

keys_rsa_enc_pkcs8_v2_2048: keys_rsa_enc_pkcs8_v2_2048_3des keys_rsa_enc_pkcs8_v2_2048_des

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des.pem
keys_rsa_enc_pkcs8_v2_4096_3des: rsa_pkcs8_pbes2_pbkdf2_4096_3des.der rsa_pkcs8_pbes2_pbkdf2_4096_3des.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des.der
rsa_pkcs8_pbes2_pbkdf2_4096_des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des.pem
keys_rsa_enc_pkcs8_v2_4096_des: rsa_pkcs8_pbes2_pbkdf2_4096_des.der rsa_pkcs8_pbes2_pbkdf2_4096_des.pem

keys_rsa_enc_pkcs8_v2_4096: keys_rsa_enc_pkcs8_v2_4096_3des keys_rsa_enc_pkcs8_v2_4096_des

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA224
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha224: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha224: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.pem

keys_rsa_enc_pkcs8_v2_1024_sha224: keys_rsa_enc_pkcs8_v2_1024_3des_sha224 keys_rsa_enc_pkcs8_v2_1024_des_sha224

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha224: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha224: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.pem

keys_rsa_enc_pkcs8_v2_2048_sha224: keys_rsa_enc_pkcs8_v2_2048_3des_sha224 keys_rsa_enc_pkcs8_v2_2048_des_sha224

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha224: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha224: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.pem

keys_rsa_enc_pkcs8_v2_4096_sha224: keys_rsa_enc_pkcs8_v2_4096_3des_sha224 keys_rsa_enc_pkcs8_v2_4096_des_sha224

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA256
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha256: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha256: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.pem

keys_rsa_enc_pkcs8_v2_1024_sha256: keys_rsa_enc_pkcs8_v2_1024_3des_sha256 keys_rsa_enc_pkcs8_v2_1024_des_sha256

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha256: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha256: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.pem

keys_rsa_enc_pkcs8_v2_2048_sha256: keys_rsa_enc_pkcs8_v2_2048_3des_sha256 keys_rsa_enc_pkcs8_v2_2048_des_sha256

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha256: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha256: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.pem

keys_rsa_enc_pkcs8_v2_4096_sha256: keys_rsa_enc_pkcs8_v2_4096_3des_sha256 keys_rsa_enc_pkcs8_v2_4096_des_sha256

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA384
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha384: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha384: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.pem

keys_rsa_enc_pkcs8_v2_1024_sha384: keys_rsa_enc_pkcs8_v2_1024_3des_sha384 keys_rsa_enc_pkcs8_v2_1024_des_sha384

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha384: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha384: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.pem

keys_rsa_enc_pkcs8_v2_2048_sha384: keys_rsa_enc_pkcs8_v2_2048_3des_sha384 keys_rsa_enc_pkcs8_v2_2048_des_sha384

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha384: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha384: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.pem

keys_rsa_enc_pkcs8_v2_4096_sha384: keys_rsa_enc_pkcs8_v2_4096_3des_sha384 keys_rsa_enc_pkcs8_v2_4096_des_sha384

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA512
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha512: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha512: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.pem

keys_rsa_enc_pkcs8_v2_1024_sha512: keys_rsa_enc_pkcs8_v2_1024_3des_sha512 keys_rsa_enc_pkcs8_v2_1024_des_sha512

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha512: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha512: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.pem

keys_rsa_enc_pkcs8_v2_2048_sha512: keys_rsa_enc_pkcs8_v2_2048_3des_sha512 keys_rsa_enc_pkcs8_v2_2048_des_sha512

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha512: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha512: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.pem

keys_rsa_enc_pkcs8_v2_4096_sha512: keys_rsa_enc_pkcs8_v2_4096_3des_sha512 keys_rsa_enc_pkcs8_v2_4096_des_sha512

###
### Rules to generate all RSA keys from a particular class
###

### Generate basic unencrypted RSA keys
keys_rsa_unenc: rsa_pkcs1_1024_clear.pem rsa_pkcs1_2048_clear.pem rsa_pkcs1_4096_clear.pem

### Generate PKCS1-encoded encrypted RSA keys
keys_rsa_enc_basic: keys_rsa_enc_basic_1024 keys_rsa_enc_basic_2048 keys_rsa_enc_basic_4096

### Generate PKCS8-v1 encrypted RSA keys
keys_rsa_enc_pkcs8_v1: keys_rsa_enc_pkcs8_v1_1024 keys_rsa_enc_pkcs8_v1_2048 keys_rsa_enc_pkcs8_v1_4096

### Generate PKCS8-v2 encrypted RSA keys
keys_rsa_enc_pkcs8_v2: keys_rsa_enc_pkcs8_v2_1024 keys_rsa_enc_pkcs8_v2_2048 keys_rsa_enc_pkcs8_v2_4096 keys_rsa_enc_pkcs8_v2_1024_sha224 keys_rsa_enc_pkcs8_v2_2048_sha224 keys_rsa_enc_pkcs8_v2_4096_sha224 keys_rsa_enc_pkcs8_v2_1024_sha256 keys_rsa_enc_pkcs8_v2_2048_sha256 keys_rsa_enc_pkcs8_v2_4096_sha256 keys_rsa_enc_pkcs8_v2_1024_sha384 keys_rsa_enc_pkcs8_v2_2048_sha384 keys_rsa_enc_pkcs8_v2_4096_sha384 keys_rsa_enc_pkcs8_v2_1024_sha512 keys_rsa_enc_pkcs8_v2_2048_sha512 keys_rsa_enc_pkcs8_v2_4096_sha512

### Generate all RSA keys
keys_rsa_all: keys_rsa_unenc keys_rsa_enc_basic keys_rsa_enc_pkcs8_v1 keys_rsa_enc_pkcs8_v2

################################################################
#### Generate various EC keys
################################################################

###
### PKCS8 encoded
###

ec_prv.pk8.der:
	$(OPENSSL) genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime192v1 -pkeyopt ec_param_enc:named_curve -out $@ -outform DER
all_final += ec_prv.pk8.der

# ### Instructions for creating `ec_prv.pk8nopub.der`,
# ### `ec_prv.pk8nopubparam.der`, and `ec_prv.pk8param.der` by hand from
# ### `ec_prv.pk8.der`.
#
# These instructions assume you are familiar with ASN.1 DER encoding and can
# use a hex editor to manipulate DER.
#
# The relevant ASN.1 definitions for a PKCS#8 encoded Elliptic Curve key are:
#
# PrivateKeyInfo ::= SEQUENCE {
#   version                   Version,
#   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
#   privateKey                PrivateKey,
#   attributes           [0]  IMPLICIT Attributes OPTIONAL
# }
#
# AlgorithmIdentifier  ::=  SEQUENCE  {
#   algorithm   OBJECT IDENTIFIER,
#   parameters  ANY DEFINED BY algorithm OPTIONAL
# }
#
# ECParameters ::= CHOICE {
#   namedCurve         OBJECT IDENTIFIER
#   -- implicitCurve   NULL
#   -- specifiedCurve  SpecifiedECDomain
# }
#
# ECPrivateKey ::= SEQUENCE {
#   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
#   privateKey     OCTET STRING,
#   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
#   publicKey  [1] BIT STRING OPTIONAL
# }
#
# `ec_prv.pk8.der` as generatde above by OpenSSL should have the following
# fields:
#
# * privateKeyAlgorithm       namedCurve
# * privateKey.parameters     NOT PRESENT
# * privateKey.publicKey      PRESENT
# * attributes                NOT PRESENT
#
# # ec_prv.pk8nopub.der
#
# Take `ec_prv.pk8.der` and remove `privateKey.publicKey`.
#
# # ec_prv.pk8nopubparam.der
#
# Take `ec_prv.pk8nopub.der` and add `privateKey.parameters`, the same value as
# `privateKeyAlgorithm.namedCurve`. Don't forget to add the explicit tag.
#
# # ec_prv.pk8param.der
#
# Take `ec_prv.pk8.der` and add `privateKey.parameters`, the same value as
# `privateKeyAlgorithm.namedCurve`. Don't forget to add the explicit tag.

ec_prv.pk8.pem: ec_prv.pk8.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8.pem
ec_prv.pk8nopub.pem: ec_prv.pk8nopub.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8nopub.pem
ec_prv.pk8nopubparam.pem: ec_prv.pk8nopubparam.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8nopubparam.pem
ec_prv.pk8param.pem: ec_prv.pk8param.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8param.pem

ec_pub.pem: ec_prv.sec1.der
	$(OPENSSL) pkey -in $< -inform DER -outform PEM -pubout -out $@
all_final += ec_pub.pem

ec_prv.sec1.comp.pem: ec_prv.sec1.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_prv.sec1.comp.pem

ec_224_prv.comp.pem: ec_224_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_224_prv.comp.pem

ec_256_prv.comp.pem: ec_256_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_256_prv.comp.pem

ec_384_prv.comp.pem: ec_384_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_384_prv.comp.pem

ec_521_prv.comp.pem: ec_521_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_521_prv.comp.pem

ec_bp256_prv.comp.pem: ec_bp256_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_bp256_prv.comp.pem

ec_bp384_prv.comp.pem: ec_bp384_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_bp384_prv.comp.pem

ec_bp512_prv.comp.pem: ec_bp512_prv.pem
	$(OPENSSL) ec -in $< -out $@ -conv_form compressed
all_final += ec_bp512_prv.comp.pem

ec_pub.comp.pem: ec_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_pub.comp.pem

ec_224_pub.comp.pem: ec_224_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_224_pub.comp.pem

ec_256_pub.comp.pem: ec_256_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_256_pub.comp.pem

ec_384_pub.comp.pem: ec_384_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_384_pub.comp.pem

ec_521_pub.comp.pem: ec_521_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_521_pub.comp.pem

ec_bp256_pub.comp.pem: ec_bp256_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_bp256_pub.comp.pem

ec_bp384_pub.comp.pem: ec_bp384_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_bp384_pub.comp.pem

ec_bp512_pub.comp.pem: ec_bp512_pub.pem
	$(OPENSSL) ec -pubin -in $< -out $@ -conv_form compressed
all_final += ec_bp512_pub.comp.pem

ec_x25519_prv.der:
	$(OPENSSL) genpkey -algorithm X25519 -out $@ -outform DER
all_final += ec_x25519_prv.der

ec_x25519_pub.der: ec_x25519_prv.der
	$(OPENSSL) pkey -in $< -inform DER -out $@ -outform DER -pubout
all_final += ec_x25519_pub.der

ec_x25519_prv.pem: ec_x25519_prv.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_x25519_prv.pem

ec_x25519_pub.pem: ec_x25519_prv.der
	$(OPENSSL) pkey -in $< -inform DER -out $@ -pubout
all_final += ec_x25519_pub.pem

ec_x448_prv.der:
	$(OPENSSL) genpkey -algorithm X448 -out $@ -outform DER
all_final += ec_x448_prv.der

ec_x448_pub.der: ec_x448_prv.der
	$(OPENSSL) pkey -in $< -inform DER -out $@ -outform DER -pubout
all_final += ec_x448_pub.der

ec_x448_prv.pem: ec_x448_prv.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_x448_prv.pem

ec_x448_pub.pem: ec_x448_prv.der
	$(OPENSSL) pkey -in $< -inform DER -out $@ -pubout
all_final += ec_x448_pub.pem

################################################################
#### Convert PEM keys to DER format
################################################################
server1.pubkey.der: server1.pubkey
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += server1.pubkey.der

rsa4096_pub.der: rsa4096_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += rsa4096_pub.der

ec_pub.der: ec_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += ec_pub.der

ec_521_pub.der: ec_521_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += ec_521_pub.der

ec_bp512_pub.der: ec_bp512_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += ec_bp512_pub.der

server1.key.der: server1.key
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += server1.key.der

rsa4096_prv.der: rsa4096_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += rsa4096_prv.der

ec_prv.sec1.der: ec_prv.sec1.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_prv.sec1.der

ec_256_long_prv.der: ec_256_long_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_256_long_prv.der

ec_521_prv.der: ec_521_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_521_prv.der

ec_521_short_prv.der: ec_521_short_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_521_short_prv.der

ec_bp512_prv.der: ec_bp512_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_bp512_prv.der

################################################################
### Generate CSRs for X.509 write test suite
################################################################

server1.req.sha1: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.sha1

parse_input/server1.req.md5 server1.req.md5: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=MD5
all_final += server1.req.md5

parse_input/server1.req.sha224 server1.req.sha224: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA224
all_final += server1.req.sha224

parse_input/server1.req.sha256 server1.req.sha256: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA256
all_final += server1.req.sha256

server1.req.sha256.ext: server1.key
	# Generating this with OpenSSL as a comparison point to test we're getting the same result
	openssl req -new -out $@ -key $< -subj '/C=NL/O=PolarSSL/CN=PolarSSL Server 1' -sha256 -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=URI:http://pki.example.com/,IP:127.1.1.0,DNS:example.com"
all_final += server1.req.sha256.ext

parse_input/server1.req.sha384 server1.req.sha384: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA384
all_final += server1.req.sha384

parse_input/server1.req.sha512 server1.req.sha512: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA512
all_final += server1.req.sha512

server1.req.cert_type: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< ns_cert_type=ssl_server subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.cert_type

server1.req.key_usage: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< key_usage=digital_signature,non_repudiation,key_encipherment subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.key_usage

server1.req.ku-ct: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< key_usage=digital_signature,non_repudiation,key_encipherment ns_cert_type=ssl_server subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.ku-ct

server1.req.key_usage_empty: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1 force_key_usage=1
all_final += server1.req.key_usage_empty

server1.req.cert_type_empty: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1 force_ns_cert_type=1
all_final += server1.req.cert_type_empty

parse_input/server1.req.commas.sha256: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL\, Commas,CN=PolarSSL Server 1" md=SHA256

# server2*

server2_pwd_ec = PolarSSLTest

server2.req.sha256: server2.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=localhost" md=SHA256
all_intermediate += server2.req.sha256

parse_input/server2.crt.der server2.crt.der: server2.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server2.crt.der

server2-sha256.crt.der: server2-sha256.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server2-sha256.crt.der

server2.key.der: server2.key
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += server2.key.der

server2.key.enc: server2.key
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(server2_pwd_ec)"
all_final += server2.key.enc

# server5*

server5.csr: server5.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += server5.csr
parse_input/server5.crt server5.crt: server5-sha256.crt
	cp $< $@
all_intermediate += server5-sha256.crt
server5-sha%.crt: server5.csr $(test_ca_crt_file_ec) $(test_ca_key_file_ec) server5.crt.openssl.v3_ext
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-extfile server5.crt.openssl.v3_ext -set_serial 9 -days 3650 \
				-sha$(@:server5-sha%.crt=%) -in $< -out $@
all_final += server5.crt server5-sha1.crt server5-sha224.crt server5-sha384.crt server5-sha512.crt

server5-badsign.crt: server5.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += server5-badsign.crt

# The use of 'Server 1' in the DN is intentional here, as the DN is hardcoded in the x509_write test suite.'
server5.req.ku.sha1: server5.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< key_usage=digital_signature,non_repudiation subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server5.req.ku.sha1

# server6*

server6.csr: server6.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += server6.csr
server6.crt: server6.csr $(test_ca_crt_file_ec) $(test_ca_key_file_ec)
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-extfile server5.crt.openssl.v3_ext -set_serial 10 -days 3650 -sha256 -in $< -out $@
all_final += server6.crt

################################################################
### Generate certificates for CRT write check tests
################################################################

### The test files use the Mbed TLS generated certificates server1*.crt,
### but for comparison with OpenSSL also rules for OpenSSL-generated
### certificates server1*.crt.openssl are offered.
###
### Known differences:
### * OpenSSL encodes trailing zero-bits in bit-strings occurring in X.509 extension
###   as unused bits, while Mbed TLS doesn't.

test_ca_server1_db = test-ca.server1.db
test_ca_server1_serial = test-ca.server1.serial
test_ca_server1_config_file = test-ca.server1.opensslconf

# server1*

parse_input/server1.crt server1.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) \
		issuer_pwd=$(test_ca_pwd_rsa) version=1 \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA1 version=3 output_file=$@
server1.allSubjectAltNames.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@ san=URI:http://pki.example.com\;IP:1.2.3.4\;DN:C=UK,O="Mbed TLS",CN="SubjectAltName test"\;DNS:example.com\;RFC822:mail@example.com
server1.long_serial.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	echo "112233445566778899aabbccddeeff0011223344" > test-ca.server1.tmp.serial
	$(OPENSSL) ca -in server1.req.sha256 -key PolarSSLTest -config test-ca.server1.test_serial.opensslconf -notext -batch -out $@
server1.80serial.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	echo "8011223344" > test-ca.server1.tmp.serial
	$(OPENSSL) ca -in server1.req.sha256 -key PolarSSLTest -config test-ca.server1.test_serial.opensslconf -notext -batch -out $@
server1.long_serial_FF.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	echo "ffffffffffffffffffffffffffffffff" > test-ca.server1.tmp.serial
	$(OPENSSL) ca -in server1.req.sha256 -key PolarSSLTest -config test-ca.server1.test_serial.opensslconf -notext -batch -out $@
server1.noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 authority_identifier=0 version=3 output_file=$@
parse_input/server1.crt.der server1.crt.der: server1.crt
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) \
		issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA1 authority_identifier=0 version=3 output_file=$@
server1.der: server1.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.commas.crt: server1.key server1.req.commas.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.commas.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += server1.crt server1.noauthid.crt server1.crt.der server1.commas.crt

parse_input/server1.key_usage.crt server1.key_usage.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 key_usage=digital_signature,non_repudiation,key_encipherment version=3 output_file=$@
server1.key_usage_noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 key_usage=digital_signature,non_repudiation,key_encipherment authority_identifier=0 version=3 output_file=$@
server1.key_usage.der: server1.key_usage.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.der

parse_input/server1.cert_type.crt server1.cert_type.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 ns_cert_type=ssl_server version=3 output_file=$@
server1.cert_type_noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 ns_cert_type=ssl_server authority_identifier=0 version=3 output_file=$@
server1.cert_type.der: server1.cert_type.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.der

server1.v1.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 version=1 output_file=$@
server1.v1.der: server1.v1.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.v1.crt server1.v1.der

server1.ca.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 is_ca=1 version=3 output_file=$@
server1.ca_noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 authority_identifier=0 is_ca=1 version=3 output_file=$@
server1.ca.der: server1.ca.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.ca.crt server1.ca_noauthid.crt server1.ca.der

server1_ca.crt: server1.crt $(test_ca_crt)
	cat server1.crt $(test_ca_crt) > $@
all_final += server1_ca.crt

parse_input/cert_sha1.crt cert_sha1.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA1" serial=7 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += cert_sha1.crt

parse_input/cert_sha224.crt cert_sha224.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA224" serial=8 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA224 version=3 output_file=$@
all_final += cert_sha224.crt

parse_input/cert_sha256.crt cert_sha256.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA256" serial=9 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += cert_sha256.crt

parse_input/cert_sha384.crt cert_sha384.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA384" serial=10 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA384 version=3 output_file=$@
all_final += cert_sha384.crt

parse_input/cert_sha512.crt cert_sha512.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA512" serial=11 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA512 version=3 output_file=$@
all_final += cert_sha512.crt

cert_example_wildcard.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=*.example.com" serial=12 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += cert_example_wildcard.crt

# OpenSSL-generated certificates for comparison
# Also provide certificates in DER format to allow
# direct binary comparison using e.g. dumpasn1
server1.crt.openssl server1.key_usage.crt.openssl server1.cert_type.crt.openssl: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_server1_config_file)
	echo "01" > $(test_ca_server1_serial)
	rm -f $(test_ca_server1_db)
	touch $(test_ca_server1_db)
	$(OPENSSL) ca -batch -passin "pass:$(test_ca_pwd_rsa)" -config $(test_ca_server1_config_file) -in server1.req.sha256 -extensions v3_ext -extfile $@.v3_ext -out $@
server1.der.openssl: server1.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.key_usage.der.openssl: server1.key_usage.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.cert_type.der.openssl: server1.cert_type.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

server1.v1.crt.openssl: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_server1_config_file)
	echo "01" > $(test_ca_server1_serial)
	rm -f $(test_ca_server1_db)
	touch $(test_ca_server1_db)
	$(OPENSSL) ca -batch -passin "pass:$(test_ca_pwd_rsa)" -config $(test_ca_server1_config_file) -in server1.req.sha256 -out $@
server1.v1.der.openssl: server1.v1.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

# To revoke certificate in the openssl database:
#
# $(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_server1_config_file) -md sha256 -crldays 365 -revoke server1.crt

crl.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_server1_config_file) -md sha1 -crldays 3653 -out $@

crl-futureRevocationDate.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file) test-ca.server1.future-crl.db  test-ca.server1.future-crl.opensslconf
	$(FAKETIME) '2028-12-31' $(OPENSSL) ca -gencrl -config test-ca.server1.future-crl.opensslconf -crldays 365 -passin "pass:$(test_ca_pwd_rsa)" -out $@

server1_all: crl.pem crl-futureRevocationDate.pem server1.crt server1.noauthid.crt server1.crt.openssl server1.v1.crt server1.v1.crt.openssl server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.crt.openssl server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.crt.openssl server1.der server1.der.openssl server1.v1.der server1.v1.der.openssl server1.key_usage.der server1.key_usage.der.openssl server1.cert_type.der server1.cert_type.der.openssl

# server2*

parse_input/server2.crt server2.crt: server2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=server2.req.sha256 serial=2 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += server2.crt

server2.der: server2.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server2.crt server2.der

server2-sha256.crt: server2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=server2.req.sha256 serial=2 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += server2-sha256.crt

# server3*

parse_input/server3.crt server3.crt: server3.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="C=NL,O=PolarSSL,CN=localhost" serial=13 \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA1 version=3 output_file=$@
all_final += server3.crt

# server4*

parse_input/server4.crt server4.crt: server4.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="C=NL,O=PolarSSL,CN=localhost" serial=8 \
		issuer_crt=$(test_ca_crt_file_ec) issuer_key=$(test_ca_key_file_ec) \
		not_before=20190210144400 not_after=20290210144400 \
		md=SHA256 version=3 output_file=$@
all_final += server4.crt

# MD5 test certificate

cert_md_test_key = $(cli_crt_key_file_rsa)

cert_md5.csr: $(cert_md_test_key)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Cert MD5" md=MD5
all_intermediate += cert_md5.csr

parse_input/cert_md5.crt cert_md5.crt: cert_md5.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=6 \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) \
		issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20000101121212 not_after=20300101121212 \
		md=MD5 version=3 output_file=$@
all_final += cert_md5.crt

# TLSv1.3 test certificates
ecdsa_secp256r1.key: ec_256_prv.pem
	cp $< $@

ecdsa_secp256r1.csr: ecdsa_secp256r1.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += ecdsa_secp256r1.csr
ecdsa_secp256r1.crt: ecdsa_secp256r1.csr
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-set_serial 77 -days 3653 -sha384 -in $< -out $@
all_final += ecdsa_secp256r1.crt ecdsa_secp256r1.key
tls13_certs: ecdsa_secp256r1.crt ecdsa_secp256r1.key

ecdsa_secp384r1.key: ec_384_prv.pem
	cp $< $@
ecdsa_secp384r1.csr: ecdsa_secp384r1.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += ecdsa_secp384r1.csr
ecdsa_secp384r1.crt: ecdsa_secp384r1.csr
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-set_serial 77 -days 3653 -sha384 -in $< -out $@
all_final += ecdsa_secp384r1.crt ecdsa_secp384r1.key
tls13_certs: ecdsa_secp384r1.crt ecdsa_secp384r1.key

ecdsa_secp521r1.key: ec_521_prv.pem
	cp $< $@
ecdsa_secp521r1.csr: ecdsa_secp521r1.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += ecdsa_secp521r1.csr
ecdsa_secp521r1.crt: ecdsa_secp521r1.csr
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-set_serial 77 -days 3653 -sha384 -in $< -out $@
all_final += ecdsa_secp521r1.crt ecdsa_secp521r1.key
tls13_certs: ecdsa_secp521r1.crt ecdsa_secp521r1.key

# PKCS7 test data
pkcs7_test_cert_1 = pkcs7-rsa-sha256-1.crt
pkcs7_test_cert_2 = pkcs7-rsa-sha256-2.crt
pkcs7_test_cert_3 = pkcs7-rsa-sha256-3.crt
pkcs7_test_file = pkcs7_data.bin

$(pkcs7_test_file):
	printf "Hello\15\n" > $@
all_final += $(pkcs7_test_file)

pkcs7_zerolendata.bin:
	printf '' > $@
all_final += pkcs7_zerolendata.bin

pkcs7_data_1.bin:
	printf "2\15\n" > $@
all_final += pkcs7_data_1.bin

# Generate signing cert
pkcs7-rsa-sha256-1.crt:
	$(OPENSSL) req -x509 -subj="/C=NL/O=PKCS7/CN=PKCS7 Cert 1" -sha256 -nodes -days 3653  -newkey rsa:2048 -keyout pkcs7-rsa-sha256-1.key -out pkcs7-rsa-sha256-1.crt
	cat pkcs7-rsa-sha256-1.crt pkcs7-rsa-sha256-1.key > pkcs7-rsa-sha256-1.pem
all_final += pkcs7-rsa-sha256-1.crt

pkcs7-rsa-sha256-2.crt:
	$(OPENSSL) req -x509 -subj="/C=NL/O=PKCS7/CN=PKCS7 Cert 2" -sha256 -nodes -days 3653  -newkey rsa:2048 -keyout pkcs7-rsa-sha256-2.key -out pkcs7-rsa-sha256-2.crt
	cat pkcs7-rsa-sha256-2.crt pkcs7-rsa-sha256-2.key > pkcs7-rsa-sha256-2.pem
all_final += pkcs7-rsa-sha256-2.crt

pkcs7-rsa-sha256-3.crt:
	$(OPENSSL) req -x509 -subj="/C=NL/O=PKCS7/CN=PKCS7 Cert 3" -sha256 -nodes -days 3653  -newkey rsa:2048 -keyout pkcs7-rsa-sha256-3.key -out pkcs7-rsa-sha256-3.crt
	cat pkcs7-rsa-sha256-3.crt pkcs7-rsa-sha256-3.key > pkcs7-rsa-sha256-3.pem
all_final += pkcs7-rsa-sha256-3.crt

pkcs7-rsa-expired.crt:
	$(FAKETIME) -f -3650d $(OPENSSL) req -x509 -subj="/C=NL/O=PKCS7/CN=PKCS7 Cert Expired" -sha256 -nodes -days 365  -newkey rsa:2048 -keyout pkcs7-rsa-expired.key -out pkcs7-rsa-expired.crt
all_final += pkcs7-rsa-expired.crt

# File with an otherwise valid signature signed with an expired cert
pkcs7_data_rsa_expired.der: pkcs7-rsa-expired.key pkcs7-rsa-expired.crt pkcs7_data.bin
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -inkey pkcs7-rsa-expired.key -signer pkcs7-rsa-expired.crt -noattr -outform DER -out $@
all_final += pkcs7_data_rsa_expired.der

# Convert signing certs to DER for testing PEM-free builds
pkcs7-rsa-sha256-1.der: $(pkcs7_test_cert_1)
	$(OPENSSL) x509 -in pkcs7-rsa-sha256-1.crt -out $@ -outform DER
all_final += pkcs7-rsa-sha256-1.der

pkcs7-rsa-sha256-2.der: $(pkcs7_test_cert_2)
	$(OPENSSL) x509 -in pkcs7-rsa-sha256-2.crt -out $@ -outform DER
all_final += pkcs7-rsa-sha256-2.der

pkcs7-rsa-expired.der: pkcs7-rsa-expired.crt
	$(OPENSSL) x509 -in pkcs7-rsa-expired.crt -out $@ -outform DER
all_final += pkcs7-rsa-expired.der

# pkcs7 signature file over zero-len data
pkcs7_zerolendata_detached.der: pkcs7_zerolendata.bin pkcs7-rsa-sha256-1.key pkcs7-rsa-sha256-1.crt
	$(OPENSSL) smime -sign -md sha256 -nocerts -noattr -in pkcs7_zerolendata.bin -inkey pkcs7-rsa-sha256-1.key -outform DER -binary -signer pkcs7-rsa-sha256-1.crt -out pkcs7_zerolendata_detached.der
all_final += pkcs7_zerolendata_detached.der

# pkcs7 signature file with CERT
pkcs7_data_cert_signed_sha256.der: $(pkcs7_test_file) $(pkcs7_test_cert_1)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -signer pkcs7-rsa-sha256-1.pem -noattr -outform DER -out $@
all_final += pkcs7_data_cert_signed_sha256.der

# pkcs7 signature file with CERT and sha1
pkcs7_data_cert_signed_sha1.der: $(pkcs7_test_file) $(pkcs7_test_cert_1)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha1 -signer pkcs7-rsa-sha256-1.pem -noattr -outform DER -out $@
all_final += pkcs7_data_cert_signed_sha1.der

# pkcs7 signature file with CERT and sha512
pkcs7_data_cert_signed_sha512.der: $(pkcs7_test_file) $(pkcs7_test_cert_1)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha512 -signer pkcs7-rsa-sha256-1.pem -noattr -outform DER -out $@
all_final += pkcs7_data_cert_signed_sha512.der

# pkcs7 signature file without CERT
pkcs7_data_without_cert_signed.der: $(pkcs7_test_file) $(pkcs7_test_cert_1)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -signer pkcs7-rsa-sha256-1.pem -nocerts -noattr -outform DER -out $@
all_final += pkcs7_data_without_cert_signed.der

# pkcs7 signature file with signature
pkcs7_data_with_signature.der: $(pkcs7_test_file) $(pkcs7_test_cert_1)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -signer pkcs7-rsa-sha256-1.pem -nocerts -noattr -nodetach -outform DER -out $@
all_final += pkcs7_data_with_signature.der

# pkcs7 signature file with two signers
pkcs7_data_multiple_signed.der: $(pkcs7_test_file) $(pkcs7_test_cert_1) $(pkcs7_test_cert_2)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -signer pkcs7-rsa-sha256-1.pem -signer pkcs7-rsa-sha256-2.pem -nocerts -noattr -outform DER -out $@
all_final += pkcs7_data_multiple_signed.der

# pkcs7 signature file with three signers
pkcs7_data_3_signed.der: $(pkcs7_test_file) $(pkcs7_test_cert_1) $(pkcs7_test_cert_2) $(pkcs7_test_cert_3)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -signer pkcs7-rsa-sha256-1.pem -signer pkcs7-rsa-sha256-2.pem -signer pkcs7-rsa-sha256-3.pem -nocerts -noattr -outform DER -out $@
all_final += pkcs7_data_3_signed.der

# pkcs7 signature file with multiple certificates
pkcs7_data_multiple_certs_signed.der: $(pkcs7_test_file) $(pkcs7_test_cert_1) $(pkcs7_test_cert_2)
	$(OPENSSL) smime -sign -binary -in pkcs7_data.bin -out $@ -md sha256 -signer pkcs7-rsa-sha256-1.pem -signer pkcs7-rsa-sha256-2.pem -noattr -outform DER -out $@
all_final += pkcs7_data_multiple_certs_signed.der

# pkcs7 signature file with corrupted CERT
pkcs7_data_signed_badcert.der: pkcs7_data_cert_signed_sha256.der
	cp pkcs7_data_cert_signed_sha256.der $@
	echo 'a1' | xxd -r -p | dd of=$@ bs=1 seek=547 conv=notrunc
all_final += pkcs7_data_signed_badcert.der

# pkcs7 signature file with corrupted signer info
pkcs7_data_signed_badsigner.der: pkcs7_data_cert_signed_sha256.der
	cp pkcs7_data_cert_signed_sha256.der $@
	echo 'a1' | xxd -r -p | dd of=$@ bs=1 seek=918 conv=notrunc
all_final += pkcs7_data_signed_badsigner.der

# pkcs7 signature file with invalid tag in signerInfo[1].serial after long issuer name
pkcs7_signerInfo_1_serial_invalid_tag_after_long_name.der: pkcs7_data_multiple_signed.der
	cp $< $@
	echo 'a1' | xxd -r -p | dd of=$@ bs=1 seek=498 conv=notrunc
all_final += pkcs7_signerInfo_1_serial_invalid_tag_after_long_name.der

# pkcs7 signature file with invalid tag in signerInfo[2]
pkcs7_signerInfo_2_invalid_tag.der: pkcs7_data_3_signed.der
	cp $< $@
	echo 'a1' | xxd -r -p | dd of=$@ bs=1 seek=810 conv=notrunc
all_final += pkcs7_signerInfo_2_invalid_tag.der

# pkcs7 signature file with corrupted signer info[1]
pkcs7_data_signed_badsigner1_badsize.der: pkcs7_data_3_signed.der
	cp pkcs7_data_3_signed.der $@
	echo '72' | xxd -p -r | dd of=$@ bs=1 seek=438 conv=notrunc
all_final += pkcs7_data_signed_badsigner1_badsize.der

pkcs7_data_signed_badsigner1_badtag.der: pkcs7_data_3_signed.der
	cp pkcs7_data_3_signed.der $@
	echo 'a1' | xxd -p -r | dd of=$@ bs=1 seek=442 conv=notrunc
all_final += pkcs7_data_signed_badsigner1_badtag.der

pkcs7_data_signed_badsigner1_fuzzbad.der: pkcs7_data_3_signed.der
	cp pkcs7_data_3_signed.der $@
	echo 'a1' | xxd -p -r | dd of=$@ bs=1 seek=550 conv=notrunc
all_final += pkcs7_data_signed_badsigner1_fuzzbad.der

# pkcs7 signature file with corrupted signer info[2]
pkcs7_data_signed_badsigner2_badsize.der: pkcs7_data_3_signed.der
	cp pkcs7_data_3_signed.der $@
	echo '72'| xxd -p -r | dd of=$@ bs=1 seek=813 conv=notrunc
all_final += pkcs7_data_signed_badsigner2_badsize.der

pkcs7_data_signed_badsigner2_badtag.der: pkcs7_data_3_signed.der
	cp pkcs7_data_3_signed.der $@
	echo 'a1'| xxd -p -r | dd of=$@ bs=1 seek=817 conv=notrunc
all_final += pkcs7_data_signed_badsigner2_badtag.der

pkcs7_data_signed_badsigner2_fuzzbad.der: pkcs7_data_3_signed.der
	cp pkcs7_data_3_signed.der $@
	echo 'a1'| xxd -p -r | dd of=$@ bs=1 seek=925 conv=notrunc
all_final += pkcs7_data_signed_badsigner2_fuzzbad.der

# pkcs7 file with version 2
pkcs7_data_cert_signed_v2.der: pkcs7_data_cert_signed_sha256.der
	cp pkcs7_data_cert_signed_sha256.der $@
	echo '02' | xxd -r -p | dd of=$@ bs=1 seek=25 conv=notrunc
all_final += pkcs7_data_cert_signed_v2.der

pkcs7_data_cert_encrypted.der: $(pkcs7_test_file) $(pkcs7_test_cert_1)
	$(OPENSSL) smime -encrypt -aes256 -in pkcs7_data.bin -binary -outform DER -out $@ pkcs7-rsa-sha256-1.crt
all_final += pkcs7_data_cert_encrypted.der

## Negative tests
# For some interesting sizes, what happens if we make them off-by-one?
pkcs7_signerInfo_issuer_invalid_size.der: pkcs7_data_cert_signed_sha256.der
	cp $< $@
	echo '35' | xxd -r -p | dd of=$@ seek=919 bs=1 conv=notrunc
all_final += pkcs7_signerInfo_issuer_invalid_size.der

pkcs7_signerInfo_serial_invalid_size.der: pkcs7_data_cert_signed_sha256.der
	cp $< $@
	echo '15' | xxd -r -p | dd of=$@ seek=973 bs=1 conv=notrunc
all_final += pkcs7_signerInfo_serial_invalid_size.der

# pkcs7 signature file just with signed data
pkcs7_data_cert_signeddata_sha256.der: pkcs7_data_cert_signed_sha256.der
	dd if=pkcs7_data_cert_signed_sha256.der of=$@ skip=19 bs=1
all_final += pkcs7_data_cert_signeddata_sha256.der

################################################################
#### Diffie-Hellman parameters
################################################################

dh.998.pem:
	$(OPENSSL) dhparam -out $@ -text 998

dh.999.pem:
	$(OPENSSL) dhparam -out $@ -text 999
