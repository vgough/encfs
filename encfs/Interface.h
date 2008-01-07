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

class ConfigVar;

// part of REL library..
namespace rel
{

    class Interface
    {
    public:

	/*!
	  Version numbers as described by libtool:  info://libtool/versioning
	  Current - the most recent interface api that is implemented.
	  Revision - the implementation number of the current interface.
	  Age - the difference between the newest and oldest interfaces that
	        are implemented.
	*/
	Interface( const char *name, int Current, int Revision, int Age );
	Interface( const std::string &name, int Current, int Revision, int Age);
	Interface(const Interface &src);
	Interface();

	// check if we implement the interface described by B.
	// Note that A.implements(B) is not the same as B.implements(A)
	// This checks the current() version and age() against B.current() for
	// compatibility.  Even if A.implements(B) is true, B > A may also be
	// true, meaning B is a newer revision of the interface then A.
	bool implements( const Interface &dst ) const;

	const std::string &name() const;
	int current() const;
	int revision() const;
	int age() const;
	
	std::string &name();
	int &current();
	int &revision();
	int &age();

	Interface &operator = ( const Interface &src );

    private:
	std::string _name;
	int _current;
	int _revision;
	int _age;
    };
	
}

ConfigVar & operator << (ConfigVar &, const rel::Interface &);
const ConfigVar & operator >> (const ConfigVar &, rel::Interface &);
    
bool operator < (const rel::Interface &A, const rel::Interface &B);
bool operator > (const rel::Interface &A, const rel::Interface &B);
bool operator <= (const rel::Interface &A, const rel::Interface &B);
bool operator >= (const rel::Interface &A, const rel::Interface &B);
bool operator == (const rel::Interface &A, const rel::Interface &B);
bool operator != (const rel::Interface &A, const rel::Interface &B);

#endif

