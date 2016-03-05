# - Try to find GCrypt
# Once done this will define
#
#  GCRYPT_FOUND - system has GCrypt
#  GCRYPT_INCLUDE_DIRS - the GCrypt include directory
#  GCRYPT_LIBRARIES - Link these to use GCrypt
#  GCRYPT_DEFINITIONS - Compiler switches required for using GCrypt
#
#=============================================================================
#  Copyright (c) 2009-2011 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

if (GCRYPT_LIBRARIES AND GCRYPT_INCLUDE_DIRS)
    # in cache already
    # set(GCRYPT_FOUND TRUE)
else (GCRYPT_LIBRARIES AND GCRYPT_INCLUDE_DIRS)

    set(_GCRYPT_ROOT_PATHS
        "$ENV{PROGRAMFILES}/libgcrypt"
    )

    find_path(GCRYPT_ROOT_DIR
        NAMES
            include/gcrypt.h
        PATHS
            ${_GCRYPT_ROOT_PATHS}
    )
    mark_as_advanced(ZLIB_ROOT_DIR)

    find_path(GCRYPT_INCLUDE_DIR
        NAMES
            gcrypt.h
        PATHS
            /usr/local/include
            /opt/local/include
            /sw/include
            /usr/lib/sfw/include
            ${GCRYPT_ROOT_DIR}/include
    )
    set(GCRYPT_INCLUDE_DIRS ${GCRYPT_INCLUDE_DIR})

    find_library(GCRYPT_LIBRARY
        NAMES
            gcrypt
            gcrypt11
            libgcrypt-11
        PATHS
            /opt/local/lib
            /sw/lib
            /usr/sfw/lib/64
            /usr/sfw/lib
            ${GCRYPT_ROOT_DIR}/lib
    )
    set(GCRYPT_LIBRARIES ${GCRYPT_LIBRARY})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(GCrypt DEFAULT_MSG GCRYPT_LIBRARIES GCRYPT_INCLUDE_DIRS)

    # show the GCRYPT_INCLUDE_DIRS and GCRYPT_LIBRARIES variables only in the advanced view
    mark_as_advanced(GCRYPT_INCLUDE_DIRS GCRYPT_LIBRARIES)

endif (GCRYPT_LIBRARIES AND GCRYPT_INCLUDE_DIRS)
