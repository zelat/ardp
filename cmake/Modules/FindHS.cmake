find_path(HS_INCLUDE_DIR
        NAMES hs_compile.h
        PATHS /usr/include/ /usr/local/include ${CMAKE_SOURCE_DIR}/ModuleMode)
find_library(HS_LIBRARY NAMES urcu PATHS /usr/local/lib /usr/lib/urcu /usr/local/lib/urcu ${CMAKE_SOURCE_DIR}/ModuleMode)

if (HS_INCLUDE_DIR AND HS_LIBRARY)
    set(HS_FOUND TRUE)
endif (HS_INCLUDE_DIR AND HS_LIBRARY)