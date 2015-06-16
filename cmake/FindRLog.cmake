# FindRLog
# --------
#
# Find RLog
#
# Find the RLog logging library.  This module defines
#
# ::
#
#   RLOG_INCLUDE_DIR, where to find rlog.h, etc.
#   RLOG_LIBRARIES, the libraries needed to use RLog.
#   RLOG_FOUND, If false, do not try to use RLog.

find_path(RLOG_INCLUDE_DIR rlog/rlog.h)

set(RLOG_NAMES ${RLOG_NAMES} rlog librlog)
find_library(RLOG_LIBRARY NAMES ${RLOG_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set RLOG_FOUND to TRUE if
# all listed variables are TRUE
include (FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(RLOG DEFAULT_MSG RLOG_LIBRARY RLOG_INCLUDE_DIR)

if(RLOG_FOUND)
  set(RLOG_LIBRARIES ${RLOG_LIBRARY})
endif()

mark_as_advanced(RLOG_LIBRARY RLOG_INCLUDE_DIR )
