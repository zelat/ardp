include(ExternalProject)

set (HS_ROOT        ${CMAKE_BINARY_DIR}/third_party/hyperscan)
set (HS_LIB_DIR     ${HS_ROOT}/lib)
set (HS_INCLUDE_DIR ${HS_ROOT}/include)

# 关闭告警
add_definitions(-Wno-dev)

set (HS_CONFIGURE    cd ${HS_ROOT}/src/hyperscan-5.4.0 && cmake -DCMAKE_INSTALL_PREFIX=${HS_ROOT} .
 -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
 -DBUILD_SHARED_LIBS=OFF
)
set (HS_CMAKE        cd ${HS_ROOT}/src/hyperscan-5.4.0 && cmake -DBUILD_SHARED_LIBS=on -DCMAKE_BUILD_TYPE=Release ..)
set (HS_MAKE         cd ${HS_ROOT}/src/hyperscan-5.4.0 && make)
set (HS_INSTALL      cd ${HS_ROOT}/src/hyperscan-5.4.0 && make install)

ExternalProject_Add(hyperscan-5.4.0
		URL			${CMAKE_SOURCE_DIR}/third_party/hyperscan/hyperscan-5.4.0.zip
		DOWNLOAD_NAME		hyperscan-5.4.0
		PREFIX				${HS_ROOT}
		CONFIGURE_COMMAND	${HS_CONFIGURE}
		BUILD_COMMAND		${HS_MAKE}
		INSTALL_COMMAND		${HS_INSTALL}
		)

include_directories (${CMAKE_BINARY_DIR}/third_party/hyperscan/include/hs)
link_directories (${CMAKE_BINARY_DIR}/third_party/hyperscan/lib64)


