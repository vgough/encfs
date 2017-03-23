/*****************************************************************************
 * Author:   danim7 (https://github.com/danim7)
 *
 *****************************************************************************
 * Copyright (c) 2017, danim7 (https://github.com/danim7)
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

#include <gcrypt.h>

#include "Error.h"

namespace encfs {

void gcrypt_init() {
  /* Version check should be the very first call because it
     makes sure that important subsystems are initialized. */
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      RLOG(ERROR) << "libgcrypt version mismatch\n";
      exit (2);
    }

  /* We don't want to see any warnings, e.g. because we have not yet
     parsed program options which might be used to suppress such
     warnings. */
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

  /* ... If required, other initialization goes here.  Note that the
     process might still be running with increased privileges and that
     the secure memory has not been initialized.  */

  /* Allocate a pool of 128 bytes secure memory.  This makes the secure memory
     available and also drops privileges where needed.  Note that by
     using functions like gcry_xmalloc_secure and gcry_mpi_snew Libgcrypt
     may extend the secure memory pool with memory which lacks the
     property of not being swapped out to disk.   */
  gcry_control (GCRYCTL_INIT_SECMEM, 128, 0);

  /* It is now okay to let Libgcrypt complain when there was/is
     a problem with the secure memory. */
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  /* ... If required, other initialization goes here.  */

  /* Tell Libgcrypt that initialization has completed. */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

}  // namespace encfs
