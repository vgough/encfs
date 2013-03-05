/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
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

#ifndef _Mutex_incl_
#define _Mutex_incl_

#include "base/config.h"

#ifdef CMAKE_USE_PTHREADS_INIT
#include <pthread.h>
#else
#warning No thread support.
#endif

namespace encfs
{

class Mutex
{
 public:
#ifdef CMAKE_USE_PTHREADS_INIT
  pthread_mutex_t _mutex;
  Mutex() {
    pthread_mutex_init( &_mutex, 0 );
  }
  ~Mutex() {
    pthread_mutex_destroy( &_mutex );
  }
#endif

  void lock();
  void unlock();
};

class Lock
{
public:
  explicit Lock( Mutex &mutex );
  ~Lock();

  // leave the lock as it is.  When the Lock wrapper is destroyed, it
  // will do nothing with the pthread mutex.
  void leave();

private:
  Lock(const Lock &src); // not allowed
  Lock &operator = (const Lock &src); // not allowed

  Mutex *_mutex;
};

inline void Mutex::lock() 
{
#ifdef CMAKE_USE_PTHREADS_INIT
  pthread_mutex_lock( &_mutex );
#endif
}

inline void Mutex::unlock()
{
#ifdef CMAKE_USE_PTHREADS_INIT
  pthread_mutex_unlock( &_mutex );
#endif
}

inline Lock::Lock( Mutex &mutex )
    : _mutex( &mutex )
{
  if (_mutex)
    _mutex->lock();
}

inline Lock::~Lock( )
{
  if(_mutex)
    _mutex->unlock();
}

inline void Lock::leave()
{
  _mutex = NULL;
}

}  // namespace encfs

#endif

