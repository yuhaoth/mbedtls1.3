Mbed TLS - Experimental branch
==============================

# Introduction

This is the experimental branch of [Mbed TLS](https://github.com/armmbed/mbedtls). For more information on Mbed TLS in
general, please see the corresponding
[README.md](https://github.com/armmbed/mbedtls/tree/development/README.md). This readme focuses on the specifics of the experimental branch.

This branch hosts the development of experimental and exploratory features of Mbed TLS. Most of the
development happening here is intended to be upstreamed to main Mbed TLS, but might not yet have reached
the necessary level of code quality and/or testing and/or documentation.

## Feedback and Contribution

If you are interested in trying out or contributing to the features that are being developed here, please reach out! We
welcome any feedback and support, and it will accelerate the process of getting the features in a production ready state
suitable for upstreaming to Mbed TLS' `development` branch.

If you want to share any feedback, just open an issue. If you've made an improvement, open a PR. And if you
have questions of any kind, drop us a line - the main points of contacts are [@hanno-arm](https://github.com/hanno-arm)
and [@hannestschofenig](https://github.com/hannestschofenig).

# Experimental Features

In the following, we describe the features that are currently under development.

## TLS 1.3

The experimental branch contains a prototype implementation of TLS 1.3. Supported features include PSK and ECDHE-based
key exchanges, 0-RTT and session tickets. The TLS 1.3 prototype is actively being worked on, see
[issues](https://github.com/hannestschofenig/mbedtls/issues) and [pull
requests](https://github.com/hannestschofenig/mbedtls/pulls), and major parts of it, such as the entire TLS 1.3 key
schedule, have already been upstreamed to the `development` branch of Mbed TLS. We aim to have completed the upstreaming
of client-only, ECDHE-only TLS 1.3 support to upstream Mbed TLS by the end of September 2021.

TLS 1.3 support is enabled by default. Please try it out and let us know if you have any issues. As mentioned, it will
accelerate the upstreaming process.

## Towards DTLS 1.3, QUIC, cTLS, and Post-Quantum Cryptography: A new Message Processing Stack (MPS)

A growing number of TLS-variants are currently in development, such as DTLS 1.3, QUIC, cTLS, or KemTLS. Some of those
variants maintain the handshake logic of TLS but change lower level details (e.g. QUIC, cTLS, DTLS 1.3), while others
keep the lower layers and change the handshake logic (e.g. KemTLS).

In order to eventually support the large number of TLS-variants with a minimal code base with maximal code sharing, we
have developed a complete rewrite of Mbed TLS' messaging layer, called _Message Processing Stack_ (MPS). MPS provides a
multiple abstraction boundariies between low-level messaging details of TLS, and the higher level handshake logic. Variants
like cTLS, DTLS 1.3, QUIC, only need to re-implement the MPS abstraction boundary, but keep the handshake logic intact,
while variants like KemTLS can keep the MPS implementation but build a different handshake layer on top.

MPS also aims to support future development around _Post Quantum Cryptography_: Specifically, it offers a _streaming
interface_ to the handshake layer, whereby handshake messages can be processed gradually as they arrive, without prior reassembly in
RAM. This allows some memory hungry Post-Quantum schemes to be implemented with small amounts of RAM.

Links: [MPS API](https://github.com/hannestschofenig/mbedtls/tree/tls13-prototype/include/mbedtls/mps), [MPS
Implementation](https://github.com/hannestschofenig/mbedtls/tree/tls13-prototype/library/mps).

MPS is controlled by the configuration option `MBEDTLS_SSL_USE_MPS`, which is enabled by default.

## Post-Quantum Cryptography

We're in the early stages of experimenting with PQC support in Mbed TLS on the basis of the [libOQS](https://openquantumsafe.org/liboqs/) post-quantum
cryptography library.  To enable libOQS, you have to set `MBEDTLS_LIBOQS_ENABLE` in `include/mbedtls/mbedtls_config.h`
and build Mbed TLS via `cmake`. Any change in `MBEDTLS_LIBOQS_ENABLE` currently demands a re-build of the `cmake`
makefiles. You can check that the build was successful by checking for and running the libOQS unit test `./tests/test_suite_liboqs`.

The actual integration PQC KEMs and their hybrids into Mbed TLS is still ongoing. Please reach out to [@brett-warren-arm](https://github.com/brett-warren-arm)
or [@hanno-arm](https://github.com/hanno-arm), or open an issue, if have questions or would like to contribute.

# Known limitations

Please consult the [issues](https://github.com/hannestschofenig/mbedtls/issues) for a complete list of issues. Here we
focus on the main limitations.

## Dual TLS 1.2 - TLS 1.3 build

If you are cross-compiling, you must set the `CC` environment variable to a C compiler for the host platform when generating the configuration-independent files.

Any of the following methods are available to generate the configuration-independent files:

* If not cross-compiling, running `make` with any target, or just `make`, will automatically generate required files.
* On non-Windows systems, when not cross-compiling, CMake will generate the required files automatically.
* Run `make generated_files` to generate all the configuration-independent files.
* On Unix/POSIX systems, run `tests/scripts/check-generated-files.sh -u` to generate all the configuration-independent files.
* On Windows, run `scripts\make_generated_files.bat` to generate all the configuration-independent files.

### Make

We require GNU Make. To build the library and the sample programs, GNU Make and a C compiler are sufficient. Some of the more advanced build targets require some Unix/Linux tools.

We intentionally only use a minimum of functionality in the makefiles in order to keep them as simple and independent of different toolchains as possible, to allow users to more easily move between different platforms. Users who need more features are recommended to use CMake.

In order to build from the source code using GNU Make, just enter at the command line:

    make

In order to run the tests, enter:

    make check

The tests need Python to be built and Perl to be run. If you don't have one of them installed, you can skip building the tests with:

    make no_test

You'll still be able to run a much smaller set of tests with:

    programs/test/selftest

In order to build for a Windows platform, you should use `WINDOWS_BUILD=1` if the target is Windows but the build environment is Unix-like (for instance when cross-compiling, or compiling from an MSYS shell), and `WINDOWS=1` if the build environment is a Windows shell (for instance using mingw32-make) (in that case some targets will not be available).

Setting the variable `SHARED` in your environment will build shared libraries in addition to the static libraries. Setting `DEBUG` gives you a debug build. You can override `CFLAGS` and `LDFLAGS` by setting them in your environment or on the make command line; compiler warning options may be overridden separately using `WARNING_CFLAGS`. Some directory-specific options (for example, `-I` directives) are still preserved.

Please note that setting `CFLAGS` overrides its default value of `-O2` and setting `WARNING_CFLAGS` overrides its default value (starting with `-Wall -Wextra`), so if you just want to add some warning options to the default ones, you can do so by setting `CFLAGS=-O2 -Werror` for example. Setting `WARNING_CFLAGS` is useful when you want to get rid of its default content (for example because your compiler doesn't accept `-Wall` as an option). Directory-specific options cannot be overridden from the command line.

Depending on your platform, you might run into some issues. Please check the Makefiles in `library/`, `programs/` and `tests/` for options to manually add or remove for specific platforms. You can also check [the Mbed TLS Knowledge Base](https://tls.mbed.org/kb) for articles on your platform or issue.

In case you find that you need to do something else as well, please let us know what, so we can add it to the [Mbed TLS Knowledge Base](https://tls.mbed.org/kb).

### CMake

In order to build the source using CMake in a separate directory (recommended), just enter at the command line:

    mkdir /path/to/build_dir && cd /path/to/build_dir
    cmake /path/to/mbedtls_source
    cmake --build .

In order to run the tests, enter:

    ctest

The test suites need Python to be built and Perl to be executed. If you don't have one of these installed, you'll want to disable the test suites with:

    cmake -DENABLE_TESTING=Off /path/to/mbedtls_source

If you disabled the test suites, but kept the programs enabled, you can still run a much smaller set of tests with:

    programs/test/selftest

To configure CMake for building shared libraries, use:

    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On /path/to/mbedtls_source

There are many different build modes available within the CMake buildsystem. Most of them are available for gcc and clang, though some are compiler-specific:

-   `Release`. This generates the default code without any unnecessary information in the binary files.
-   `Debug`. This generates debug information and disables optimization of the code.
-   `Coverage`. This generates code coverage information in addition to debug information.
-   `ASan`. This instruments the code with AddressSanitizer to check for memory errors. (This includes LeakSanitizer, with recent version of gcc and clang.) (With recent version of clang, this mode also instruments the code with UndefinedSanitizer to check for undefined behaviour.)
-   `ASanDbg`. Same as ASan but slower, with debug information and better stack traces.
-   `MemSan`. This instruments the code with MemorySanitizer to check for uninitialised memory reads. Experimental, needs recent clang on Linux/x86\_64.
-   `MemSanDbg`. Same as MemSan but slower, with debug information, better stack traces and origin tracking.
-   `Check`. This activates the compiler warnings that depend on optimization and treats all warnings as errors.

Switching build modes in CMake is simple. For debug mode, enter at the command line:

    cmake -D CMAKE_BUILD_TYPE=Debug /path/to/mbedtls_source

To list other available CMake options, use:

    cmake -LH

Note that, with CMake, you can't adjust the compiler or its flags after the
initial invocation of cmake. This means that `CC=your_cc make` and `make
CC=your_cc` will *not* work (similarly with `CFLAGS` and other variables).
These variables need to be adjusted when invoking cmake for the first time,
for example:

    CC=your_cc cmake /path/to/mbedtls_source

If you already invoked cmake and want to change those settings, you need to
remove the build directory and create it again.

Note that it is possible to build in-place; this will however overwrite the
provided Makefiles (see `scripts/tmp_ignore_makefiles.sh` if you want to
prevent `git status` from showing them as modified). In order to do so, from
the Mbed TLS source directory, use:

    cmake .
    make

If you want to change `CC` or `CFLAGS` afterwards, you will need to remove the
CMake cache. This can be done with the following command using GNU find:

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +

You can now make the desired change:

    CC=your_cc cmake .
    make

Regarding variables, also note that if you set CFLAGS when invoking cmake,
your value of CFLAGS doesn't override the content provided by cmake (depending
on the build mode as seen above), it's merely prepended to it.

#### Consuming Mbed TLS

Mbed TLS provides a package config file for consumption as a dependency in other
CMake projects. You can include Mbed TLS's CMake targets yourself with:

    find_package(MbedTLS)

If prompted, set `MbedTLS_DIR` to `${YOUR_MBEDTLS_INSTALL_DIR}/cmake`. This
creates the following targets:

- `MbedTLS::mbedcrypto` (Crypto library)
- `MbedTLS::mbedtls` (TLS library)
- `MbedTLS::mbedx509` (X509 library)

You can then use these directly through `target_link_libraries()`:

    add_executable(xyz)

    target_link_libraries(xyz
        PUBLIC MbedTLS::mbedtls
               MbedTLS::mbedcrypto
               MbedTLS::mbedx509)

This will link the Mbed TLS libraries to your library or application, and add
its include directories to your target (transitively, in the case of `PUBLIC` or
`INTERFACE` link libraries).

#### Mbed TLS as a subproject

Mbed TLS supports being built as a CMake subproject. One can
use `add_subdirectory()` from a parent CMake project to include Mbed TLS as a
subproject.

### Microsoft Visual Studio

The build files for Microsoft Visual Studio are generated for Visual Studio 2010.

The solution file `mbedTLS.sln` contains all the basic projects needed to build the library and all the programs. The files in tests are not generated and compiled, as these need Python and perl environments as well. However, the selftest program in `programs/test/` is still available.

In the development branch of Mbed TLS, the Visual Studio solution files need to be generated first as described in [“Generated source files in the development branch”](#generated-source-files-in-the-development-branch).

Example programs
----------------

We've included example programs for a lot of different features and uses in [`programs/`](programs/README.md).
Please note that the goal of these sample programs is to demonstrate specific features of the library, and the code may need to be adapted to build a real-world application.

Tests
-----

Mbed TLS includes an elaborate test suite in `tests/` that initially requires Python to generate the tests files (e.g. `test\_suite\_mpi.c`). These files are generated from a `function file` (e.g. `suites/test\_suite\_mpi.function`) and a `data file` (e.g. `suites/test\_suite\_mpi.data`). The `function file` contains the test functions. The `data file` contains the test cases, specified as parameters that will be passed to the test function.

For machines with a Unix shell and OpenSSL (and optionally GnuTLS) installed, additional test scripts are available:

-   `tests/ssl-opt.sh` runs integration tests for various TLS options (renegotiation, resumption, etc.) and tests interoperability of these options with other implementations.
-   `tests/compat.sh` tests interoperability of every ciphersuite with other implementations.
-   `tests/scripts/test-ref-configs.pl` test builds in various reduced configurations.
-   `tests/scripts/key-exchanges.pl` test builds in configurations with a single key exchange enabled
-   `tests/scripts/all.sh` runs a combination of the above tests, plus some more, with various build options (such as ASan, full `mbedtls_config.h`, etc).

Porting Mbed TLS
----------------

Mbed TLS can be ported to many different architectures, OS's and platforms. Before starting a port, you may find the following Knowledge Base articles useful:

-   [Porting Mbed TLS to a new environment or OS](https://tls.mbed.org/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS)
-   [What external dependencies does Mbed TLS rely on?](https://tls.mbed.org/kb/development/what-external-dependencies-does-mbedtls-rely-on)
-   [How do I configure Mbed TLS](https://tls.mbed.org/kb/compiling-and-building/how-do-i-configure-mbedtls)

Mbed TLS is mostly written in portable C99; however, it has a few platform requirements that go beyond the standard, but are met by most modern architectures:

- Bytes must be 8 bits.
- All-bits-zero must be a valid representation of a null pointer.
- Signed integers must be represented using two's complement.
- `int` and `size_t` must be at least 32 bits wide.
- The types `uint8_t`, `uint16_t`, `uint32_t` and their signed equivalents must be available.

PSA cryptography API
--------------------

### PSA API design

Arm's [Platform Security Architecture (PSA)](https://developer.arm.com/architectures/security-architectures/platform-security-architecture) is a holistic set of threat models, security analyses, hardware and firmware architecture specifications, and an open source firmware reference implementation. PSA provides a recipe, based on industry best practice, that allows security to be consistently designed in, at both a hardware and firmware level.

The [PSA cryptography API](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface) provides access to a set of cryptographic primitives. It has a dual purpose. First, it can be used in a PSA-compliant platform to build services, such as secure boot, secure storage and secure communication. Second, it can also be used independently of other PSA components on any platform.

The design goals of the PSA cryptography API include:

* The API distinguishes caller memory from internal memory, which allows the library to be implemented in an isolated space for additional security. Library calls can be implemented as direct function calls if isolation is not desired, and as remote procedure calls if isolation is desired.
* The structure of internal data is hidden to the application, which allows substituting alternative implementations at build time or run time, for example, in order to take advantage of hardware accelerators.
* All access to the keys happens through key identifiers, which allows support for external cryptoprocessors that is transparent to applications.
* The interface to algorithms is generic, favoring algorithm agility.
* The interface is designed to be easy to use and hard to accidentally misuse.

Arm welcomes feedback on the design of the API. If you think something could be improved, please open an issue on our Github repository. Alternatively, if you prefer to provide your feedback privately, please email us at [`mbed-crypto@arm.com`](mailto:mbed-crypto@arm.com). All feedback received by email is treated confidentially.

### PSA API documentation

A browsable copy of the PSA Cryptography API documents is available on the [PSA cryptography interfaces documentation portal](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface) in [PDF](https://armmbed.github.io/mbed-crypto/PSA_Cryptography_API_Specification.pdf) and [HTML](https://armmbed.github.io/mbed-crypto/html/index.html) formats.

### PSA implementation in Mbed TLS

Mbed TLS includes a reference implementation of the PSA Cryptography API.
However, it does not aim to implement the whole specification; in particular it does not implement all the algorithms.

The X.509 and TLS code can use PSA cryptography for most operations. To enable this support, activate the compilation option `MBEDTLS_USE_PSA_CRYPTO` in `mbedtls_config.h`. Note that TLS 1.3 uses PSA cryptography for most operations regardless of this option. See `docs/use-psa-crypto.md` for details.

### Upcoming features

Future releases of this library will include:

* A driver programming interface, which makes it possible to use hardware accelerators instead of the default software implementation for chosen algorithms.
* Support for external keys to be stored and manipulated exclusively in a separate cryptoprocessor.
* A configuration mechanism to compile only the algorithms you need for your application.
* A wider set of cryptographic algorithms.

License
-------

Unless specifically indicated otherwise in a file, Mbed TLS files are provided under the [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) license. See the [LICENSE](LICENSE) file for the full text of this license. Contributors must accept that their contributions are made under both the Apache-2.0 AND [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) licenses. This enables LTS (Long Term Support) branches of the software to be provided under either the Apache-2.0 OR GPL-2.0-or-later licenses.

Contributing
------------

We gratefully accept bug reports and contributions from the community. Please see the [contributing guidelines](CONTRIBUTING.md) for details on how to do this.

Contact
-------

* To report a security vulnerability in Mbed TLS, please email <mbed-tls-security@lists.trustedfirmware.org>. For more information, see [`SECURITY.md`](SECURITY.md).
* To report a bug or request a feature in Mbed TLS, please [file an issue on GitHub](https://github.com/Mbed-TLS/mbedtls/issues/new/choose).
* Please see [`SUPPORT.md`](SUPPORT.md) for other channels for discussion and support about Mbed TLS.
