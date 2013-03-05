/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004-2013, Valient Gough
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
                             
#include "base/Interface.h"

#include "base/ConfigVar.h"

#include <glog/logging.h>
#include <ostream>

namespace encfs {

std::ostream& operator << (std::ostream& out, const Interface &iface) 
{
  out << iface.name() << "(" << iface.major() 
      << ":" << iface.minor() << ":" << iface.age() << ")";
  return out;
}

bool implements(const Interface &A, const Interface &B) 
{
  VLOG(1) << "checking if " << A << " implements " << B;

  if( A.name() != B.name() )
    return false;

  int currentDiff = A.major() - B.major();
  return ( currentDiff >= 0 && currentDiff <= (int)A.age() );
}

Interface makeInterface(const char *name, int major, int minor, int age)
{
  Interface iface;
  iface.set_name(name);
  iface.set_major(major);
  iface.set_minor(minor);
  iface.set_age(age);
  return iface;
}

ConfigVar & operator << (ConfigVar &dst, const Interface &iface)
{
  dst << iface.name() << (int)iface.major() << (int)iface.minor()
      << (int)iface.age();
  return dst;
}

const ConfigVar & operator >> (const ConfigVar &src, Interface &iface)
{
  src >> *iface.mutable_name();
  int major, minor, age;
  src >> major >> minor >> age;
  iface.set_major(major);
  iface.set_minor(minor);
  iface.set_age(age);
  return src;
}

bool operator != (const Interface &a, const Interface &b)
{
  if (a.major() != b.major())
    return true;

  if (a.minor() != b.minor())
    return true;

  return false;
}

}  // namespace encfs
