#ifndef _Error_incl_
#define _Error_incl_

#include <glog/logging.h>
#include <stdexcept>

class Error : public std::runtime_error
{
public:
  Error(const char *msg);
};

#define STR(X) #X

#define rAssert( cond ) \
  do { \
    if( (cond) == false) \
    { LOG(ERROR) << "Assert failed: " << STR(cond); \
      throw Error(STR(cond)); \
    } \
  } while(0)


#endif

