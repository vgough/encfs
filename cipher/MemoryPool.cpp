/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2013, Valient Gough
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

#include "cipher/MemoryPool.h"

#include <cstdlib>
#include <cstring>

#include "base/config.h"
#include "base/Error.h"

#include <pthread.h>

#include <sys/mman.h>

#include <glog/logging.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_NOACCESS( a, b )
#define VALGRIND_MAKE_MEM_UNDEFINED( a, b )
#endif

#include <map>
#include <list>

using namespace std;

# include <openssl/crypto.h>
# include <openssl/buffer.h>

namespace encfs {

static BUF_MEM *allocBlock( int size )
{
    BUF_MEM *block = BUF_MEM_new( );
    BUF_MEM_grow( block, size );
    VALGRIND_MAKE_MEM_NOACCESS( block->data, block->max );

    return block;
}

static void freeBlock( BUF_MEM *block )
{
    VALGRIND_MAKE_MEM_UNDEFINED( block->data, block->max );
    BUF_MEM_free( block );
}

static pthread_mutex_t gMPoolMutex = PTHREAD_MUTEX_INITIALIZER;

typedef std::map<int, std::list<BUF_MEM* > > FreeBlockMap;
static FreeBlockMap gFreeBlocks;

void MemBlock::allocate(int size)
{
    rAssert(size > 0);
    pthread_mutex_lock( &gMPoolMutex );

    list<BUF_MEM*> &freeList = gFreeBlocks[size];
    BUF_MEM *mem;

    if (!freeList.empty())
    {
      mem = freeList.front();
      freeList.pop_front();
      pthread_mutex_unlock( &gMPoolMutex );
    } else
    {
      pthread_mutex_unlock( &gMPoolMutex );
      mem = allocBlock( size );
    }

    internalData = mem;
    data = reinterpret_cast<byte *>(mem->data);
    VALGRIND_MAKE_MEM_UNDEFINED( data, size );
}

MemBlock::~MemBlock()
{
    BUF_MEM *block = (BUF_MEM*)internalData;
    data = NULL;
    internalData = NULL;

    if (block)
    {
      // wipe the buffer..
      VALGRIND_MAKE_MEM_UNDEFINED( block->data, block->max );
      memset( block->data , 0, block->max);
      VALGRIND_MAKE_MEM_NOACCESS( block->data, block->max );

      pthread_mutex_lock( &gMPoolMutex );
      gFreeBlocks[ block->max ].push_front(block);
      pthread_mutex_unlock( &gMPoolMutex );
    }
}

void MemoryPool::destroyAll()
{
    pthread_mutex_lock( &gMPoolMutex );

    for (FreeBlockMap::const_iterator it = gFreeBlocks.begin();
         it != gFreeBlocks.end(); it++)
    {
      for (list<BUF_MEM*>::const_iterator bIt = it->second.begin();
           bIt != it->second.end(); bIt++)
      {
        freeBlock( *bIt );
      }
    }
   
    gFreeBlocks.clear();

    pthread_mutex_unlock( &gMPoolMutex );
}

SecureMem::SecureMem(int len)
{
  rAssert(len > 0);
  data = (byte *)OPENSSL_malloc(len);
  if (data)
  {
    size = len;
    mlock(data, size);
    memset(data, '\0', size);
    VALGRIND_MAKE_MEM_UNDEFINED( data, size );
  } else
  {
    size = 0;
  }
} 
          
SecureMem::~SecureMem()
{
  if (size)
  {
    memset(data, '\0', size);
    OPENSSL_cleanse(data, size);

    munlock(data, size);
    OPENSSL_free(data);
    VALGRIND_MAKE_MEM_NOACCESS( data, size );

    data = NULL;
    size = 0;
  }
}         
          
}  // namespace encfs

