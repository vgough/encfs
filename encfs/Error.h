#ifndef _Error_incl_
#define _Error_incl_

// Provides compatibility with RLog's rAssert, which throws an Error exception.

#include "spdlog/spdlog.h"
#include <stdexcept>

namespace encfs {

#define LOG spdlog::get("global")

class Error : public std::runtime_error {
 public:
  Error(const char *msg);
};

#define STR(X) #X

#define rAssert(cond)                             \
  do {                                            \
    if ((cond) == false) {                        \
      LOG->error("Assert failed: {}", STR(cond)); \
      throw encfs::Error(STR(cond));              \
    }                                             \
  } while (0)

#define CHECK_EQ(l, r) rAssert(l == r)

void initLogging(bool enable_debug = false);

// Calling enable_syslog replaces the logger sink with a syslog sink.
void enable_syslog();

}  // namespace encfs

#endif
