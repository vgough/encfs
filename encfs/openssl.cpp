/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2007, Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "openssl.h"

#include <openssl/crypto.h>
#include <pthread.h>
#include <stdlib.h>

#define NO_DES
#include <openssl/rand.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "Error.h"

namespace encfs {

unsigned long pthreads_thread_id() { return (unsigned long)pthread_self(); }

static pthread_mutex_t *crypto_locks = NULL;
void pthreads_locking_callback(int mode, int n, const char *caller_file,
                               int caller_line) {
  (void)caller_file;
  (void)caller_line;

  if (!crypto_locks) {
    VLOG(1) << "Allocating " << CRYPTO_num_locks() << " locks for OpenSSL";
    crypto_locks = new pthread_mutex_t[CRYPTO_num_locks()];
    for (int i = 0; i < CRYPTO_num_locks(); ++i)
      pthread_mutex_init(crypto_locks + i, 0);
  }

  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(crypto_locks + n);
  } else {
    pthread_mutex_unlock(crypto_locks + n);
  }
}

void pthreads_locking_cleanup() {
  if (crypto_locks) {
    for (int i = 0; i < CRYPTO_num_locks(); ++i)
      pthread_mutex_destroy(crypto_locks + i);
    delete[] crypto_locks;
    crypto_locks = NULL;
  }
}

void openssl_init(bool threaded) {
  // initialize the SSL library
  SSL_load_error_strings();
  SSL_library_init();

  unsigned int randSeed = 0;
  RAND_bytes((unsigned char *)&randSeed, sizeof(randSeed));
  srand(randSeed);

#ifndef OPENSSL_NO_ENGINE
  /* Load all bundled ENGINEs into memory and make them visible */
  ENGINE_load_builtin_engines();
  /* Register all of them for every algorithm they collectively implement */
  ENGINE_register_all_complete();
#endif  // NO_ENGINE

  if (threaded) {
    // provide locking functions to OpenSSL since we'll be running with
    // threads accessing openssl in parallel.
    CRYPTO_set_id_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
  }
}

void openssl_shutdown(bool threaded) {
#ifndef OPENSSL_NO_ENGINE
  ENGINE_cleanup();
#endif

  if (threaded) pthreads_locking_cleanup();
}

}  // namespace encfs
