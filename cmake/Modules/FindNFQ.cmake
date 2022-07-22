find_path(NFQ_INCLUDE_DIR
        NAMES libnetfilter_queue.h
        PATHS /usr/include/ /usr/local/include /usr/local/include/libnetfilter_queue ${CMAKE_SOURCE_DIR}/ModuleMode)
find_library(NFQ_LIBRARY
        NAMES netfilter_queue
        PATHS /usr/local/lib /usr/lib/libnetfilter_queue /usr/local/lib/libnetfilter_queue ${CMAKE_SOURCE_DIR}/ModuleMode)

if (NFQ_INCLUDE_DIR AND NFQ_LIBRARY)
    set(NFQ_FOUND TRUE)
endif (NFQ_INCLUDE_DIR AND NFQ_LIBRARY)