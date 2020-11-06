#!/usr/bin/env bash

# This script reads the output STDOUT log from the instrumented mbedTLS code
# and groups all of the cryptoprimitive calls by their context. The context
# is a 6-byte long pointer. By the extracting this pointer text from the file
# the contexts can be grouped by temporal order of the functions that call
# the context. (Note: if a function is not instrumented, it will not appear
# in the log file, thus not appearing here).
#
# In addition to the temporal flow of the functions operating on the contexts,
# it extracts the "context state" debug message from the handshake funciton.
# The appearance of these messages (see the compound grep in phase 2) indicates
# where in the handshake the functions were invoked.
# 
# Example output:
#
# ---
# --- NEW CONTEXT 0x7ffdcac1d700
# ---
# pule: mbedtls_sha256_init(0x7ffdcac1d700)
# pule: mbedtls_sha256_starts(0x7ffdcac1d700)
# pule: mbedtls_sha256_update:ilen = 197 (0x7ffdcac1d700)
# pule: mbedtls_sha256_finish(0x7ffdcac1d700)
# pule: mbedtls_sha256_free(0x7ffdcac1d700)

file=$1

if [ "$file" == "" ]; then
    echo "Please specify the output file containing the ssl_client invocation STDOUT."
    exit 1
fi

# Grep #1: Extract 'pule' debug lines
# Sed #1: Sometimes pules interrupt mbedtls_printfs before they finish, so clear that
# Grep #2: Exract those lines with a context handle (hex long ptr)
# Sed #2: Extract just the unique context address
# Uniquify the contexts
ctxs=`grep pule ${file} \
    | sed 's/^.*pule/pule/' \
    | grep 0x \
    | sed 's/^.*\(0x[0-9a-h]\+\).*$/\1/i' \
    | sort -u`

# Now that we know all the unique contexts, grep their appearances in-order, grouped
for ctx in $ctxs ; do 
	echo "---"
	echo "--- NEW CONTEXT ${ctx}"
	echo "---"
    # Compound grep also extracts all of the handshake states, in order, so we can
    # later tell in which state the function was called.
    # Note: the open paren ')' on ctx is for "clone(src->dst)" functions, to make sure
    #       we only grep the RHS of the clone arrow.
	grep "client state\|${ctx})" ${file}
done

