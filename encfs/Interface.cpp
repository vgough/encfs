/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
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

#include "Interface.h"

#include <utility>

#include "ConfigVar.h"
#include "Error.h"

namespace encfs {

Interface::Interface(const char *name_, int Current, int Revision, int Age)
    : _name(name_), _current(Current), _revision(Revision), _age(Age) {}

Interface::Interface(std::string name_, int Current, int Revision, int Age)
    : _name(std::move(name_)),
      _current(Current),
      _revision(Revision),
      _age(Age) {}

Interface::Interface() : _current(0), _revision(0), _age(0) {}

Interface &Interface::operator=(const Interface &src) = default;

const std::string &Interface::name() const { return _name; }

std::string &Interface::name() { return _name; }

int Interface::current() const { return _current; }

int &Interface::current() { return _current; }

int Interface::revision() const { return _revision; }

int &Interface::revision() { return _revision; }

int Interface::age() const { return _age; }

int &Interface::age() { return _age; }

bool operator==(const Interface &A, const Interface &B) {
  return (A.name() == B.name() && A.current() == B.current() &&
          A.revision() == B.revision() && A.age() == B.age());
}

bool operator!=(const Interface &A, const Interface &B) {
  return (A.name() != B.name() || A.current() != B.current() ||
          A.revision() != B.revision() || A.age() != B.age());
}

// zero branch method of getting comparison sign..
// tricky.. makes assumptions
#if 0
static int sign( int a, int b )
{
    unsigned int ab = ((unsigned int)(a - b)) >> 31;
    unsigned int ba = ((unsigned int)(b - a)) >> 31;

    return 1 + ba - ab;
}
#else
// simple, easy to check, unlikely to break due to unforseen events..
static int sign(int a, int b) {
  if (a < b) {
    return 0;
  }
  if (a == b) {
    return 1;
  }
  return 2;
}
#endif

static int diffSum(const Interface &A, const Interface &B) {
  int cS = sign(A.current(), B.current());
  int aS = sign(A.age(), B.age());
  int rS = sign(A.revision(), B.revision());

  return (cS * 3 + aS) * 3 + rS;
}

const int EqualVersion = (1 * 3 + 1) * 3 + 1;

bool Interface::implements(const Interface &B) const {
  VLOG(1) << "checking if " << name() << "(" << current() << ":" << revision()
          << ":" << age() << ") implements " << B.name() << "(" << B.current()
          << ":" << B.revision() << ")";

  if (name() != B.name()) {
    return false;
  }

  int currentDiff = current() - B.current();
  return (currentDiff >= 0 && currentDiff <= age());
}

bool operator<(const Interface &A, const Interface &B) {
  if (A.name() == B.name()) {
    return (diffSum(A, B) < EqualVersion);
  }
  return A.name() < B.name();
}

bool operator>(const Interface &A, const Interface &B) {
  if (A.name() == B.name()) {
    return (diffSum(A, B) > EqualVersion);
  }
  return A.name() < B.name();
}

bool operator<=(const Interface &A, const Interface &B) {
  if (A.name() == B.name()) {
    return (diffSum(A, B) <= EqualVersion);
  }
  return A.name() < B.name();
}

bool operator>=(const Interface &A, const Interface &B) {
  if (A.name() == B.name()) {
    return (diffSum(A, B) >= EqualVersion);
  }
  return A.name() < B.name();
}

ConfigVar &operator<<(ConfigVar &dst, const Interface &iface) {
  dst << iface.name() << iface.current() << iface.revision() << iface.age();
  return dst;
}

const ConfigVar &operator>>(const ConfigVar &src, Interface &iface) {
  src >> iface.name();
  src >> iface.current();
  src >> iface.revision();
  src >> iface.age();
  return src;
}

}  // namespace encfs
