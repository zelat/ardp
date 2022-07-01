include(ExternalProject)

set (JANSSON_ROOT        ${CMAKE_BINARY_DIR}/third_party/jansson)
set (JANSSON_LIB_DIR     ${JANSSON_ROOT}/lib)
set (JANSSON_INCLUDE_DIR ${JANSSON_ROOT}/include)

set (JANSSON_CONFIGURE    cd ${JANSSON_ROOT}/src/jansson-2.14 && cmake -DCMAKE_INSTALL_PREFIX=${JANSSON_ROOT} .
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DBUILD_SHARED_LIBS=OFF
        )
set (JANSSON_MAKE         cd ${JANSSON_ROOT}/src/jansson-2.14 && make)
set (JANSSON_INSTALL      cd ${JANSSON_ROOT}/src/jansson-2.14 && make install)

ExternalProject_Add(jansson-2.14
        URL			${CMAKE_SOURCE_DIR}/third_party/jansson/jansson-2.14.zip
        DOWNLOAD_NAME		jansson-2.14
        PREFIX				${JANSSON_ROOT}
        CONFIGURE_COMMAND	${JANSSON_CONFIGURE}
        BUILD_COMMAND		${JANSSON_MAKE}
        INSTALL_COMMAND		${JANSSON_INSTALL}
        )

include_directories (${CMAKE_BINARY_DIR}/third_party/jansson/include)
link_directories (${CMAKE_BINARY_DIR}/third_party/jansson/lib)


