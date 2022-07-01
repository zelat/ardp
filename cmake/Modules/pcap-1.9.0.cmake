include(ExternalProject)

set (PCAP_ROOT        ${CMAKE_BINARY_DIR}/third_party/pcap)
set (PCAP_LIB_DIR     ${PCAP_ROOT}/lib)
set (PCAP_INCLUDE_DIR ${PCAP_ROOT}/include)

set (PCAP_CONFIGURE    cd ${PCAP_ROOT}/src/pcap-1.9.0 && cmake -DCMAKE_INSTALL_PREFIX=${PCAP_ROOT} .
 -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
 -DBUILD_SHARED_LIBS=OFF
)  
set (PCAP_MAKE         cd ${PCAP_ROOT}/src/pcap-1.9.0 && make)
set (PCAP_INSTALL      cd ${PCAP_ROOT}/src/pcap-1.9.0 && make install)

ExternalProject_Add(pcap-1.9.0
		URL			${CMAKE_SOURCE_DIR}/third_party/pcap/libpcap-1.9.0.zip
		DOWNLOAD_NAME		pcap-1.9.0
		PREFIX			${PCAP_ROOT}
		CONFIGURE_COMMAND	${PCAP_CONFIGURE}
		BUILD_COMMAND		${PCAP_MAKE}
		INSTALL_COMMAND		${PCAP_INSTALL}
		)

include_directories (${CMAKE_BINARY_DIR}/third_party/pcap/include)
link_directories (${CMAKE_BINARY_DIR}/third_party/pcap/lib)


