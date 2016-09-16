#include "Error.h"

namespace encfs {

el::base::DispatchAction rlogAction = el::base::DispatchAction::NormalLog;

Error::Error(const char *msg) : runtime_error(msg) {}

void initLogging(bool enable_debug) {
  el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);

  el::Configurations defaultConf;
  defaultConf.setToDefault();
  defaultConf.set(el::Level::Verbose, el::ConfigurationType::Format,
                  std::string("%datetime %level [%fbase:%line] %msg"));
  defaultConf.set(el::Level::Global, el::ConfigurationType::ToFile, "false");
  if (!enable_debug) {
    defaultConf.set(el::Level::Debug, el::ConfigurationType::Enabled, "false");
  }
  el::Loggers::reconfigureLogger("default", defaultConf);
}

}  // namespace encfs
