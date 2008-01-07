/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
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

#ifndef _Mutex_incl_
#define _Mutex_incl_

#include <pthread.h>

namespace rel
{

    class Lock
    {
    public:
	Lock( pthread_mutex_t &mutex );
	~Lock();

	// leave the lock as it is.  When the Lock wrapper is destroyed, it
	// will do nothing with the pthread mutex.
	void leave();

    private:
	Lock(const Lock &src); // not allowed
	Lock &operator = (const Lock &src); // not allowed

	pthread_mutex_t *_mutex;
    };

    inline Lock::Lock( pthread_mutex_t &mutex )
	 : _mutex( &mutex )
    {
	pthread_mutex_lock( _mutex );
    }

    inline Lock::~Lock( )
    {
	if(_mutex)
	    pthread_mutex_unlock( _mutex );
    }

    inline void Lock::leave()
    {
	_mutex = 0;
    }
}

#endif

