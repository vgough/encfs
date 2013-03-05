
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
#include "cipher/MAC.h"
#include "cipher/testing.h"

using namespace encfs;

namespace {

TEST(HMacSha1Test, MAC) {
  Registry<MAC> registry = MAC::GetRegistry();
  shared_ptr<MAC> hmac( registry.CreateForMatch( NAME_SHA1_HMAC ));
  ASSERT_FALSE(!hmac);

  // Test cases from rfc2202
  // Test case 1
  CipherKey key(20);
  byte out[20];
  for (int i = 0; i < 20; ++i)
    key.data()[i] = 0x0b;
  hmac->setKey(key);
  hmac->init();
  hmac->update((byte *)"Hi There", 8);
  hmac->write(out);
  ASSERT_EQ("b617318655057264e28bc0b6fb378c8ef146be00", stringToHex(out, 20));

  // Test case 2
  key = CipherKey((const byte *)"Jefe", 4);
  hmac->setKey(key);
  hmac->init();
  hmac->update((byte *)"what do ya want for nothing?", 28);
  hmac->write(out);
  ASSERT_EQ("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", stringToHex(out, 20));

  // Test case 3
  key = CipherKey(20);
  for (int i = 0; i < 20; ++i)
    key.data()[i] = 0xaa;
  hmac->setKey(key);
  hmac->init();
  {
    byte data[50];
    memset(data, 0xdd, 50);
    hmac->update(data, 50);
  }
  hmac->write(out);
  ASSERT_EQ("125d7342b9ac11cd91a39af48aa17b4f63f175d3", stringToHex(out, 20));

  // Test #7
  key = CipherKey(80);
  memset(key.data(), 0xaa, 80);
  hmac->setKey(key);
  hmac->init();
  hmac->update((byte *)"Test Using Larger Than Block-Size Key and Larger "
               "Than One Block-Size Data", 73);
  hmac->write(out);
  ASSERT_EQ("e8e99d0f45237d786d6bbaa7965c7808bbff1a91", stringToHex(out, 20));
}


}  // namespace

