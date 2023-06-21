## This file contains a record of how some of the test data was
## generated. The final build products are committed to the repository
## as well to make sure that the test data is identical. You do not
## need to use this makefile unless you're extending mbed TLS's tests.

## Many data files were generated prior to the existence of this
## makefile, so the method of their generation was not recorded.

## Note that in addition to depending on the version of the data
## generation tool, many of the build outputs are randomized, so
## running this makefile twice would not produce the same results.

## Tools
OPENSSL ?= openssl
FAKETIME ?= faketime

TOP_DIR = $(shell git rev-parse --show-toplevel)
MBEDTLS_CERT_WRITE ?= $(TOP_DIR)/programs/x509/cert_write
MBEDTLS_CERT_REQ ?= $(TOP_DIR)/programs/x509/cert_req


## Build the generated test data. Note that since the final outputs
## are committed to the repository, this target should do nothing on a
## fresh checkout. Furthermore, since the generation is randomized,
## re-running the same targets may result in differing files. The goal
## of this makefile is primarily to serve as a record of how the
## targets were generated in the first place.
default: all_final

all_intermediate := # temporary files
all_final := # files used by tests


################################################################
#### Meta targets
################################################################

all_final: $(all_final)
all: $(all_intermediate) $(all_final)

.PHONY: default all_final all

# These files should not be committed to the repository.
list_intermediate:
	@printf '%s\n' $(all_intermediate) | sort
# These files should be committed to the repository so that the test data is
# available upon checkout without running a randomized process depending on
# third-party tools.
list_final:
	@printf '%s\n' $(all_final) | sort
.PHONY: list_intermediate list_final

## Remove intermediate files
clean:
	rm -f $(all_intermediate)
## Remove all build products, even the ones that are committed
neat: clean
	rm -f $(all_final)
.PHONY: clean neat

.SECONDARY: $(all_intermediate)
