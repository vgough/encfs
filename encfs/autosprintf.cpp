/* Class autosprintf - formatted output to an ostream.
   Copyright (C) 2002 Free Software Foundation, Inc.
   Written by Bruno Haible <bruno@clisp.org>, 2002.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Library General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/* Tell glibc's <stdio.h> to provide a prototype for vasprintf().
   This must come before <config.h> because <config.h> may include
   <features.h>, and once <features.h> has been included, it's too late.  */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

/* Specification.  */
#include "autosprintf.h"

#include <cstdarg>  // for va_list
#include <cstdio>   // for NULL, vasprintf
#include <cstdlib>  // for free
#include <cstring>  // for strdup

namespace gnu {

/* Constructor: takes a format string and the printf arguments.  */
autosprintf::autosprintf(const char *format, ...) { // NOLINT (cert-dcl50-cpp) as it's not critical
  va_list args;
  va_start(args, format);
  if (vasprintf(&str, format, args) < 0) {
    str = nullptr;
  }
  va_end(args);
}

/* Copy constructor.  Necessary because the destructor is nontrivial.  */
autosprintf::autosprintf(const autosprintf &src) {
  str = (src.str != nullptr ? strdup(src.str) : nullptr);
}

/* Destructor: frees the temporarily allocated string.  */
autosprintf::~autosprintf() {
  free(str); // NOLINT (cppcoreguidelines-no-malloc) as it's a consequence of vasprintf / variadic function above
}

/* Conversion to string.  */
autosprintf::operator char *() const {
  if (str != nullptr) {
    size_t length = strlen(str) + 1;
    auto *copy = new char[length];
    memcpy(copy, str, length);
    return copy;
  }
  return nullptr;
}
autosprintf::operator std::string() const {
  return std::string(str != nullptr ? str : "(error in autosprintf)");
}
}  // namespace gnu
