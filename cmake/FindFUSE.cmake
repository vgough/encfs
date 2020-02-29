# Find the FUSE includes and library
#
# FUSE_INCLUDE_DIR - where to find fuse.h, etc.
# FUSE_LIBRARIES   - List of libraries when using FUSE.
# FUSE_ROOT_DIR    - Additional search path.
# FUSE_FOUND       - True if FUSE lib is found.

# check if already in cache, be silent
if (FUSE_INCLUDE_DIR AND FUSE_LIBRARIES)
    SET (FUSE_FIND_QUIETLY TRUE)
endif ()

if (APPLE)
    set (FUSE_NAMES libosxfuse.dylib fuse)
    set (FUSE_SUFFIXES osxfuse fuse)
else ()
    set (FUSE_NAMES fuse refuse)
    set (FUSE_SUFFIXES fuse refuse)
endif ()

# find include
find_path (
    FUSE_INCLUDE_DIR fuse.h
    PATHS /opt /opt/local /usr /usr/local /usr/pkg ${FUSE_ROOT_DIR} ENV FUSE_ROOT_DIR
    PATH_SUFFIXES include ${FUSE_SUFFIXES})

# find lib
find_library (
    FUSE_LIBRARIES
    NAMES ${FUSE_NAMES}
    PATHS /opt /opt/local /usr /usr/local /usr/pkg ${FUSE_ROOT_DIR} ENV FUSE_ROOT_DIR
    PATH_SUFFIXES lib)

include ("FindPackageHandleStandardArgs")
find_package_handle_standard_args (
    "FUSE" DEFAULT_MSG
    FUSE_INCLUDE_DIR FUSE_LIBRARIES)

mark_as_advanced (FUSE_INCLUDE_DIR FUSE_LIBRARIES)
