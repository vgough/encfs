#include "Error.h"

INITIALIZE_EASYLOGGINGPP

namespace encfs {

el::base::DispatchAction rlogAction = el::base::DispatchAction::NormalLog;

Error::Error(const char *msg) : runtime_error(msg) {}

void initLogging(bool enable_debug, bool is_daemon) {

  el::Configurations defaultConf;
  defaultConf.setToDefault();
  defaultConf.set(el::Level::Global, el::ConfigurationType::ToFile, "false");
  std::string prefix = "%datetime ";
  std::string suffix = " [%fbase:%line]";
  if (is_daemon) {
    prefix = "";
    encfs::rlogAction = el::base::DispatchAction::SysLog;
  }
  else {
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
  }
  if (!enable_debug) {
    suffix = "";
    defaultConf.set(el::Level::Debug, el::ConfigurationType::Enabled, "false");
  }
  else {
    el::Loggers::setVerboseLevel(1);
  }
  defaultConf.setGlobally(el::ConfigurationType::Format, prefix + std::string("%level %msg") + suffix);
  el::Loggers::reconfigureLogger("default", defaultConf);
}

}  // namespace encfs
