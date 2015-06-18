/* Class autosprintf - formatted output to an ostream.
   Copyright (C) 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU Library General Public License as published
   by the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
   USA.  */

#ifndef _AUTOSPRINTF_H
#define _AUTOSPRINTF_H

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5) || __STRICT_ANSI__
#define __attribute__(Spec) /* empty */
#endif
/* The __-protected variants of `format' and `printf' attributes
   are accepted by gcc versions 2.6.4 (effectively 2.7) and later.  */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#define __format__ format
#define __printf__ printf
#endif
#endif

#include <iostream>
#include <string>

namespace gnu {
/* A temporary object, usually allocated on the stack, representing
   the result of an asprintf() call.  */
class autosprintf {
 public:
  /* Constructor: takes a format string and the printf arguments.  */
  autosprintf(const char* format, ...)
      __attribute__((__format__(__printf__, 2, 3)));
  /* Copy constructor.  */
  autosprintf(const autosprintf& src);
  /* Destructor: frees the temporarily allocated string.  */
  ~autosprintf();
  /* Conversion to string.  */
  operator char*() const;
  operator std::string() const;
  /* Output to an ostream.  */
  friend inline std::ostream& operator<<(std::ostream& stream,
                                         const autosprintf& tmp) {
    stream << (tmp.str ? tmp.str : "(error in autosprintf)");
    return stream;
  }

 private:
  char* str;
};
}

#endif /* _AUTOSPRINTF_H */
