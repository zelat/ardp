include(ExternalProject)

set (LNQ_ROOT        ${CMAKE_BINARY_DIR}/third_party/libnetfilter_queue)
set (LNQ_LIB_DIR     ${LNQ_ROOT}/lib)
set (LNQ_INCLUDE_DIR ${LNQ_ROOT}/include)

set (LNQ_CONFIGURE    cd ${LNQ_ROOT}/src/libnetfilter_queue && chmod 755 configure && ./configure --prefix=${LNQ_ROOT})
set (LNQ_MAKE         cd ${LNQ_ROOT}/src/libnetfilter_queue && make)
set (LNQ_INSTALL      cd ${LNQ_ROOT}/src/libnetfilter_queue && make install)

ExternalProject_Add(libnetfilter_queue
        URL			${CMAKE_SOURCE_DIR}/third_party/libnetfilter_queue
        DOWNLOAD_NAME		libnetfilter_queue
        PREFIX				${LNQ_ROOT}
        CONFIGURE_COMMAND	${LNQ_CONFIGURE}
        BUILD_COMMAND		${LNQ_MAKE}
        INSTALL_COMMAND		${LNQ_INSTALL}
        )

include_directories (${CMAKE_BINARY_DIR}/third_party/libnetfilter_queue/include)
link_directories (${CMAKE_BINARY_DIR}/third_party/libnetfilter_queue/lib)


