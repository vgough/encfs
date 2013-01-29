#include "base/Error.h"

Error::Error(const char *msg)
    : runtime_error(msg)
{
}

