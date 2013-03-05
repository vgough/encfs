
#include <gtest/gtest.h>

#include "cipher/testing.h"

namespace encfs {

static const char hexLut[] = "0123456789abcdef";

std::string stringToHex(const byte *data, int len) {
  std::string out;
  out.reserve(2 * len);
  for (int i = 0; i < len; ++i) {
    unsigned int c = (unsigned int)data[i] & 0xff;
    int first = (unsigned int)c >> 4;
    int second = (unsigned int)c & 15;

    out.push_back(hexLut[first]);
    out.push_back(hexLut[second]);
  }
  return out;
}

void setDataFromHex(byte *out, int len, const char *hex) {
  bool odd = false;
  unsigned int last = 0;
  while (len > 0 && *hex != '\0') {
    byte nibble = *hex++;
    if (nibble >= '0' && nibble <= '9') 
      nibble -= '0';
    else if (nibble >= 'A' && nibble <= 'F')
      nibble -= 'A' - 10;
    else if (nibble >= 'a' && nibble <= 'f')
      nibble -= 'a' - 10;
    else
      nibble = 0;

    last |= (unsigned int)nibble;
    if (odd) {
      *out++ = (byte)last;
      --len;
      last = 0;
      odd = false;
    } else {
      last <<= 4;
      odd = true;
    }
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

}  // namespace encfs

