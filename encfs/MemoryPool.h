/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (LGPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 *
 */

#ifndef _MemoryPool_incl_
#define _MemoryPool_incl_


struct MemBlock
{
    unsigned char *data;

    void *internalData;

    MemBlock();
};

inline MemBlock::MemBlock()
    : data(0), internalData(0)
{
}

/*
    Memory Pool for fixed sized objects.

    Usage:
    MemBlock mb = MemoryPool::allocate( size );
    // do things with storage in   mb.data
    unsigned char *buffer = mb.data;
    MemoryPool::release( mb );
*/
namespace MemoryPool
{
    MemBlock allocate( int size );
    void release( const MemBlock &el );
    void destroyAll();
}

#endif

