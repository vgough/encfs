
/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2013 Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.  
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <string.h>

#include <gtest/gtest.h>

#include "base/shared_ptr.h"
#include "cipher/PBKDF.h"
#include "cipher/testing.h"

using namespace encfs;

namespace {

TEST(PKCS5_PBKDF2_HMAC_SHA1, PBKDF) {
  Registry<PBKDF> registry = PBKDF::GetRegistry();
  shared_ptr<PBKDF> impl( registry.CreateForMatch(NAME_PBKDF2_HMAC_SHA1));
  ASSERT_FALSE(!impl);

  // Test cases from rfc6070
  // Test case 1
  {
    CipherKey key(20);
    bool ok = impl->makeKey("password", 8, 
                            (byte*)"salt", 4,
                            1, &key);
    ASSERT_TRUE(ok);
    ASSERT_EQ("0c60c80f961f0e71f3a9b524af6012062fe037a6", stringToHex(key));
  }

  {
    CipherKey key(25);
    bool ok = impl->makeKey("passwordPASSWORDpassword", 24, 
                            (byte*)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                            4096, &key);
    ASSERT_TRUE(ok);
    ASSERT_EQ("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
              stringToHex(key));
  }

  {
    CipherKey key(16);
    bool ok = impl->makeKey("pass\0word", 9, 
                            (byte*)"sa\0lt", 5,
                            4096, &key);
    ASSERT_TRUE(ok);
    ASSERT_EQ("56fa6aa75548099dcc37d7f03425e0c3", stringToHex(key));
  }
}

TEST(PKCS5_PBKDF2_HMAC_SHA256, PBKDF) {
  Registry<PBKDF> registry = PBKDF::GetRegistry();
  shared_ptr<PBKDF> impl(
          registry.CreateForMatch(NAME_PBKDF2_HMAC_SHA256));
  ASSERT_FALSE(!impl);

  // Test case 1
  {
    CipherKey key(32);
    bool ok = impl->makeKey("password", 8, 
                            (byte*)"salt", 4,
                            1, &key);
    ASSERT_TRUE(ok);
    ASSERT_EQ("120fb6cffcf8b32c"
              "43e7225256c4f837"
              "a86548c92ccc3548"
              "0805987cb70be17b", stringToHex(key));
  }

  // Test case 2
  {
    CipherKey key(40);
    bool ok = impl->makeKey("passwordPASSWORDpassword", 24, 
                            (byte*)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                            4096, &key);
    ASSERT_TRUE(ok);
    ASSERT_EQ("348c89dbcbd32b2f"
              "32d814b8116e84cf"
              "2b17347ebc180018"
              "1c4e2a1fb8dd53e1"
              "c635518c7dac47e9",
              stringToHex(key));
  }

  // Test case 3
  {
    CipherKey key(16);
    bool ok = impl->makeKey("pass\0word", 9, 
                            (byte*)"sa\0lt", 5,
                            4096, &key);
    ASSERT_TRUE(ok);
    ASSERT_EQ("89b69d0516f829893c696226650a8687", stringToHex(key));
  }
}

}  // namespace

