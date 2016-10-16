/*****************************************************************************
 * Author:   Rogelio Dominguez Hernandez <rogelio.dominguez@gmail.com>
 *
 *****************************************************************************
 * Copyright (c) 2016, Rogelio Dominguez Hernandez
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

#ifndef _SSL_Compat_incl_
#define _SSL_Compat_incl_

// OpenSSL < 1.1.0
#if OPENSSL_VERSION_NUMBER < 0x10100000L

// Equivalent methods
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define HMAC_CTX_reset HMAC_CTX_cleanup

// Missing methods (based on 1.1.0 versions)
HMAC_CTX *HMAC_CTX_new(void)
{
  HMAC_CTX *ctx = (HMAC_CTX *)OPENSSL_malloc(sizeof(HMAC_CTX));
  if (ctx != NULL) {
    memset(ctx, 0, sizeof(HMAC_CTX));
    HMAC_CTX_reset(ctx);
  }
  return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
  if (ctx != NULL) {
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
  }
}
#endif

#endif
