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
                             
#include "Interface.h"

#include "ConfigVar.h"

#include <rlog/rlog.h>
#include <rlog/RLogChannel.h>

using namespace rlog;

static RLogChannel * Info = DEF_CHANNEL( "info/iface", Log_Info );

bool implements(const Interface &A, const Interface &B) 
{
  rLog(Info, "checking if %s(%i:%i:%i) implements %s(%i:%i:%i)",
      A.name().c_str(), A.major(), A.minor(), A.age(),
      B.name().c_str(), B.major(), B.minor(), B.age());

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
  dst << iface.name() << (int)iface.major() << (int)iface.minor() << (int)iface.age();
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

const XmlValuePtr & operator >> (const XmlValuePtr &src, Interface &iface)
{
    (*src)["name"] >> *iface.mutable_name();
    int major, minor;
    (*src)["major"] >> major;
    (*src)["minor"] >> minor;
    iface.set_major(major);
    iface.set_minor(minor);
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

