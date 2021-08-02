include(ExternalProject)
ExternalProject_Add(liboqs
	GIT_REPOSITORY             https://github.com/open-quantum-safe/liboqs
	GIT_TAG                    main
	CMAKE_CACHE_ARGS           -DOQS_ENABLE_KEM_CLASSIC_MCELIECE:BOOL=OFF -DOQS_USE_OPENSSL:BOOL=OFF -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}
	)
