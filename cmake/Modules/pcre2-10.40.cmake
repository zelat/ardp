include(ExternalProject)

set(CMAKE_C_FLAGS "-std=c99")

set (PCRE2_ROOT        ${CMAKE_BINARY_DIR}/third_party/pcre2)
set (PCRE2_LIB_DIR     ${PCRE2_ROOT}/lib)
set (PCRE2_INCLUDE_DIR ${PCRE2_ROOT}/include)

set (PCRE2_CONFIGURE    cd ${PCRE2_ROOT}/src/pcre2-10.40 && export CFLAGS="-std=c99" && cmake -DCMAKE_INSTALL_PREFIX=${PCRE2_ROOT} . -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
set (PCRE2_MAKE         cd ${PCRE2_ROOT}/src/pcre2-10.40 && make)
set (PCRE2_INSTALL      cd ${PCRE2_ROOT}/src/pcre2-10.40 && make install)

ExternalProject_Add(pcre2-10.40
        URL			${CMAKE_SOURCE_DIR}/third_party/pcre2/pcre2-10.40.zip
        DOWNLOAD_NAME		pcre2-10.40
        PREFIX				${PCRE2_ROOT}
        CONFIGURE_COMMAND	${PCRE2_CONFIGURE}
        BUILD_COMMAND		${PCRE2_MAKE}
        INSTALL_COMMAND		${PCRE2_INSTALL}
        )

include_directories (${CMAKE_BINARY_DIR}/third_party/pcre2/include)
link_directories (${CMAKE_BINARY_DIR}/third_party/pcre2/lib)


