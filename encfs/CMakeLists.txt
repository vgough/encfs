
include_directories (${Encfs_SOURCE_DIR}/base)
link_directories (${Encfs_BINARY_DIR}/base)

include_directories (${Encfs_SOURCE_DIR}/cipher)
link_directories (${Encfs_BINARY_DIR}/cipher)

include_directories (${Encfs_SOURCE_DIR}/fs)
link_directories (${Encfs_BINARY_DIR}/fs)

# TODO: move FUSE code into encfs-fs.
find_package (FUSE REQUIRED)
include_directories (${FUSE_INCLUDE_DIR})

include_directories (${CMAKE_BINARY_DIR}/base)

add_executable (encfs
    main.cpp)
target_link_libraries (encfs
    encfs-fs
    encfs-cipher
    encfs-base
    ${GLOG_LIBRARIES}
    ${FUSE_LIBRARIES}
)

if (POD2MAN)
    add_custom_target(man ALL
        COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION}
        --center="Encrypted Filesystem"
        ${CMAKE_CURRENT_SOURCE_DIR}/encfs.pod
        encfs.1)
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/encfs.1
        DESTINATION
        share/man/man1)
endif (POD2MAN)

install (TARGETS encfs DESTINATION bin)

