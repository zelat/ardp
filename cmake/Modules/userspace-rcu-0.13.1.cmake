include(ExternalProject)

set (URCU_ROOT        ${CMAKE_BINARY_DIR}/third_party/urcu)
set (URCU_LIB_DIR     ${URCU_ROOT}/lib)
set (URCU_INCLUDE_DIR ${URCU_ROOT}/include)

set (URCU_CONFIGURE    cd ${URCU_ROOT}/src/userspace-rcu-0.13.1 && ./bootstrap && ./configure --prefix=${URCU_ROOT})
set (URCU_MAKE         cd ${URCU_ROOT}/src/userspace-rcu-0.13.1 && make)
set (URCU_INSTALL      cd ${URCU_ROOT}/src/userspace-rcu-0.13.1 && make install)

ExternalProject_Add(userspace-rcu-0.13.1
        URL			${CMAKE_SOURCE_DIR}/third_party/urcu/userspace-rcu-0.13.1.zip
        DOWNLOAD_NAME		userspace-rcu-0.13.1
        PREFIX				${URCU_ROOT}
        CONFIGURE_COMMAND	${URCU_CONFIGURE}
        BUILD_COMMAND		${URCU_MAKE}
        INSTALL_COMMAND		${URCU_INSTALL}
        )

include_directories (${CMAKE_BINARY_DIR}/third_party/urcu/include)
link_directories (${CMAKE_BINARY_DIR}/third_party/urcu/lib)


