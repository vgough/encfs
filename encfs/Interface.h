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

#ifndef _Interface_incl_
#define _Interface_incl_

#include <string>

namespace encfs {

class ConfigVar;

class Interface {
 public:
  /*!
    Version numbers as described by libtool:  info://libtool/versioning
    Current - the most recent interface api that is implemented.
    Revision - the implementation number of the current interface.
    Age - the difference between the newest and oldest interfaces that
          are implemented.
  */
  Interface(const char *name, int Current, int Revision, int Age);
  Interface(std::string name, int Current, int Revision, int Age);
  Interface();

  // check if we implement the interface described by B.
  // Note that A.implements(B) is not the same as B.implements(A)
  // This checks the current() version and age() against B.current() for
  // compatibility.  Even if A.implements(B) is true, B > A may also be
  // true, meaning B is a newer revision of the interface then A.
  bool implements(const Interface &dst) const;

  const std::string &name() const;
  int current() const;
  int revision() const;
  int age() const;

  std::string &name();
  int &current();
  int &revision();
  int &age();

  Interface &operator=(const Interface &src);

 private:
  std::string _name;
  int _current;
  int _revision;
  int _age;
};

ConfigVar &operator<<(ConfigVar &, const Interface &);
const ConfigVar &operator>>(const ConfigVar &, Interface &);

bool operator<(const Interface &A, const Interface &B);
bool operator>(const Interface &A, const Interface &B);
bool operator<=(const Interface &A, const Interface &B);
bool operator>=(const Interface &A, const Interface &B);
bool operator==(const Interface &A, const Interface &B);
bool operator!=(const Interface &A, const Interface &B);

}  // namespace encfs

#endif
