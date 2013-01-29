# Try to find the libglog libraries
# Once done this will define :
#
# Glog_FOUND - system has libglog
# Glog_INCLUDE_DIRS - the libglog include directory
# Glog_LIBRARIES - libglog library

# Inputs to this module:
# GLOG_ROOT       The preferred installation prefix for searching for glog. Set
#         this if the module has problems finding the proper glog installation.

# If GLOG_ROOT was defined in the environment, use it.
IF (NOT GLOG_ROOT AND NOT $ENV{GLOG_ROOT} STREQUAL "")
  SET(GLOG_ROOT $ENV{GLOG_ROOT})
ENDIF(NOT GLOG_ROOT AND NOT $ENV{GLOG_ROOT} STREQUAL "")
IF( GLOG_ROOT )
  file(TO_CMAKE_PATH ${GLOG_ROOT} GLOG_ROOT)
ENDIF( GLOG_ROOT )

SET (GLOG_INCLUDE_DIRS)
SET (GLOG_LIBRARIES)
IF(WIN32)
  IF(MSVC)
    FIND_PATH(GLOG_INCLUDE_DIRS NAMES src/windows/glog/logging.h HINTS ${GLOG_ROOT})
    IF(GLOG_INCLUDE_DIRS)
      SET(GLOG_INCLUDE_DIRS ${GLOG_INCLUDE_DIRS}/src/windows)
    ENDIF(GLOG_INCLUDE_DIRS)

    IF (CMAKE_BUILD_TYPE STREQUAL "Release")
      message (STATUS "    searching ${GLOG_ROOT}/Release/libglog.lib ...")
      FIND_LIBRARY(GLOG_LIBRARIES NAMES libglog.lib HINTS ${GLOG_ROOT}/Release $ENV{LIB} PATH_SUFFIXES ".lib")
    ELSE (CMAKE_BUILD_TYPE STREQUAL "Release")
      message (STATUS "    searching ${GLOG_ROOT}/Debug/libglog.lib ...")
      FIND_LIBRARY(GLOG_LIBRARIES NAMES libglog.lib HINTS ${GLOG_ROOT}/Debug $ENV{LIB} PATH_SUFFIXES ".lib")
    ENDIF (CMAKE_BUILD_TYPE STREQUAL "Release")
  ELSE(MSVC)
    SET(Glog_FOUND FALSE)
    message (STATUS "    Crap. this module supports only MSVC in Windows.")
  ENDIF(MSVC)
ELSE(WIN32)
  FIND_PATH(GLOG_INCLUDE_DIRS NAMES glog/logging.h HINTS ${GLOG_ROOT}/include ${GLOG_ROOT} /include/ /usr/include/ /usr/local/include/ /opt/local/include/)
  FIND_LIBRARY(GLOG_LIBRARIES NAMES glog HINTS ${GLOG_ROOT}/lib ${GLOG_ROOT} /lib /usr/lib /usr/local/lib /opt/local/lib)
ENDIF(WIN32)

IF(GLOG_INCLUDE_DIRS AND GLOG_LIBRARIES)
  SET(Glog_FOUND TRUE)
  message (STATUS "    glog found in include=${GLOG_INCLUDE_DIRS},lib=${GLOG_LIBRARIES}")
ELSE(GLOG_INCLUDE_DIRS AND GLOG_LIBRARIES)
  SET(Glog_FOUND FALSE)
  message (STATUS "    glog not found. Please set GLOG_ROOT to the root directory containing glog.")
  IF(GLOG_INCLUDE_DIRS)
    message (STATUS "    include=${GLOG_INCLUDE_DIRS}, but lib not found")
  ENDIF(GLOG_INCLUDE_DIRS)
  IF(GLOG_LIBRARIES)
    message (STATUS "    lib=${GLOG_LIBRARIES}, but include not found")
  ENDIF(GLOG_LIBRARIES)
ENDIF(GLOG_INCLUDE_DIRS AND GLOG_LIBRARIES)

MARK_AS_ADVANCED(GLOG_INCLUDE_DIRS GLOG_LIBRARIES)
