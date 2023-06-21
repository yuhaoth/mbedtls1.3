This foler contains makefile rulers to generate test data.

The final build products are committed to the repository as well to make sure
that the test data is identical. You do not need to use this makefile unless
you're extending mbed TLS's tests.

Run `tests/scripts/faketime-all.sh 'test_regenerate_*'` to make sure it is not
broken.
