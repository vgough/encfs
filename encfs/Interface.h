/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 * 
 * This program is free software; you can distribute it and/or modify it under 
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _Interface_incl_
#define _Interface_incl_

#include <string>
#include "XmlReader.h"
#include "config.pb.h"

// check if A implements the interface described by B.
// Note that implements(A, B) is not the same as implements(B, A)
// This checks the current() version and age() against B.current() for
// compatibility.  Even if A.implements(B) is true, B > A may also be
// true, meaning B is a newer revision of the interface then A.
bool implements( const Interface &a, const Interface &b );
Interface makeInterface( const char *name, int major, int minor, int age );

// Reae operation
class ConfigVar;
const ConfigVar & operator >> (const ConfigVar &, Interface &);
const XmlValuePtr & operator >> (const XmlValuePtr &, Interface &);

bool operator != (const Interface &a, const Interface &b);

#endif

