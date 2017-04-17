#include "Error.h"

namespace encfs {

Error::Error(const char *msg) : runtime_error(msg) {}

void initLogging(bool enable_debug, bool is_daemon) {

  (void) enable_debug;
  (void) is_daemon;

}

}  // namespace encfs
