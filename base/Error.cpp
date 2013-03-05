#include "base/Error.h"

namespace encfs {

Error::Error(const char *msg)
    : runtime_error(msg)
{
}

}  // namespace encfs
