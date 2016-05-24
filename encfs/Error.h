#ifndef _Error_incl_
#define _Error_incl_

// Provides compatibility with RLog's rAssert, which throws an Error exception.

#include "internal/easylogging++.h"
#include <stdexcept>

namespace encfs {

class Error : public std::runtime_error {
 public:
  Error(const char *msg);
};

#define STR(X) #X

#define rAssert(cond)                                \
  do {                                               \
    if ((cond) == false) {                           \
      RLOG(ERROR) << "Assert failed: " << STR(cond); \
      throw encfs::Error(STR(cond));                 \
    }                                                \
  } while (0)

void initLogging(bool enable_debug = false);

// This can be changed to change log action between normal and syslog logging.
// Not thread-safe, so any change must occur outside of threading context.
extern el::base::DispatchAction rlogAction;

#define RLOG(LEVEL, ...) \
  C##LEVEL(el::base::Writer, rlogAction, ELPP_CURR_FILE_LOGGER_ID)

}  // namespace encfs

#endif
