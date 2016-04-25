/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2008, Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <memory>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include "Cipher.h"
#include "CipherKey.h"
#include "openssl.h"

using namespace std;
using namespace encfs;

INITIALIZE_EASYLOGGINGPP

void genKey(const std::shared_ptr<Cipher> &cipher) {
  CipherKey key = cipher->newRandomKey();

  // encode with itself
  string b64Key = cipher->encodeAsString(key, key);

  cout << b64Key << "\n";
}

int main(int argc, char **argv) {
  pid_t pid = getpid();
  cerr << "pid = " << pid << "\n";

  if (argc != 3) {
    cerr << "usage: makeKey [AES|Blowfish] [128|160|192|224|256]\n";
    return 1;
  }

  const char *type = argv[1];
  int size = atoi(argv[2]);

  openssl_init(false);

  // get a list of the available algorithms
  std::shared_ptr<Cipher> cipher = Cipher::New(type, size);
  genKey(cipher);

  // openssl_shutdown(false);
}
