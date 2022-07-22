find_path(URCU_INCLUDE_DIR
        NAMES urcu urcu-cds
        PATHS /usr/local/include ${CMAKE_SOURCE_DIR}/ModuleMode)
find_library(URCU_LIBRARY
        NAMES urcu urcu-cds
        PATHS /usr/local/lib ${CMAKE_SOURCE_DIR}/ModuleMode)

if (URCU_INCLUDE_DIR AND URCU_LIBRARY)
    set(URCU_FOUND TRUE)
endif (URCU_INCLUDE_DIR AND URCU_LIBRARY)