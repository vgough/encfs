
#define rAssert(cond)     \
  if (!(cond)) {          \
    __coverity_panic__(); \
  }

#define CHECK_EQ(l, r)    \
  if ((l) != (r)) {       \
    __coverity_panic__(); \
  }
