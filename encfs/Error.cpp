#include "Error.h"
#include <sys/syslog.h>

namespace encfs {

Error::Error(const char *msg) : runtime_error(msg) {}

void initLogging(bool enable_debug) {
  // Multithreaded console logger(with color support)
  auto console = spdlog::stdout_color_mt("global");

  if (enable_debug) {
    console->set_level(spdlog::level::debug);
  } else {
    console->set_level(spdlog::level::info);
  }
}

void enable_syslog() {
  spdlog::drop("global");
  std::string ident = "encfs";
#ifdef SPDLOG_ENABLE_SYSLOG
  auto logger = spdlog::syslog_logger("global", ident, LOG_PID);
#else
  LOG->info("syslog not supported")
#endif
}

}  // namespace encfs
