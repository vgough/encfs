
/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2012 Valient Gough
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

#ifndef _SHARED_PTR_incl_
#define _SHARED_PTR_incl_

#include "config.h"

#ifdef HAVE_TR1_MEMORY
  #include <tr1/memory>
  using std::tr1::shared_ptr;
  using std::tr1::dynamic_pointer_cast;
#else
  #include <memory>
  using std::shared_ptr;
  using std::dynamic_pointer_cast;
#endif

#endif

