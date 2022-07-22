find_path(URCU_INCLUDE_DIR
        NAMES urcu urcu-cds
        PATHS /usr/local/include/urcu ${CMAKE_SOURCE_DIR}/ModuleMode)
find_library(URCU_LIBRARY
        NAMES urcu urcu-cds
        PATHS /usr/local/lib /usr/lib/urcu /usr/local/lib/urcu ${CMAKE_SOURCE_DIR}/ModuleMode)

if (URCU_INCLUDE_DIR AND URCU_LIBRARY)
    set(URCU_FOUND TRUE)
endif (URCU_INCLUDE_DIR AND URCU_LIBRARY)