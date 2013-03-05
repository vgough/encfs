
#include <gtest/gtest.h>

#include "cipher/testing.h"

namespace encfs {

std::string stringToHex(const byte *data, int len) {
  static const char lookup[] = "0123456789abcdef";

  std::string out;
  out.reserve(2 * len);
  for (int i = 0; i < len; ++i) {
    unsigned int c = (unsigned int)data[i] & 0xff;
    int first = (unsigned int)c >> 4;
    int second = (unsigned int)c & 15;

    out.push_back(lookup[first]);
    out.push_back(lookup[second]);
  }
  return out;
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

}  // namespace encfs

