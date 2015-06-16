# Find the FUSE includes and library
#
#  FUSE_INCLUDE_DIR - where to find fuse.h, etc.
#  FUSE_LIBRARIES   - List of libraries when using FUSE.
#  FUSE_FOUND       - True if FUSE lib is found.

# check if already in cache, be silent
if (FUSE_INCLUDE_DIR)
        SET (FUSE_FIND_QUIETLY TRUE)
endif (FUSE_INCLUDE_DIR)

if (APPLE)
    set (FUSE_NAMES libosxfuse.dylib fuse)
    set (FUSE_SUFFIXES osxfuse fuse)
else (APPLE)
    set (FUSE_NAMES fuse)
    set (FUSE_SUFFIXES fuse)
endif (APPLE)

# find includes
find_path (FUSE_INCLUDE_DIR fuse.h
        PATHS /opt /opt/local /usr/pkg
        PATH_SUFFIXES ${FUSE_SUFFIXES})

# find lib
find_library (FUSE_LIBRARIES NAMES ${FUSE_NAMES})

include ("FindPackageHandleStandardArgs")
find_package_handle_standard_args ("FUSE" DEFAULT_MSG
    FUSE_INCLUDE_DIR FUSE_LIBRARIES)

mark_as_advanced (FUSE_INCLUDE_DIR FUSE_LIBRARIES)

