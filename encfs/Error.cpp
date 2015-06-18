#include "Error.h"

namespace encfs {

el::base::DispatchAction rlogAction = el::base::DispatchAction::NormalLog;

Error::Error(const char *msg) : runtime_error(msg) {}

}  // namespace encfs
