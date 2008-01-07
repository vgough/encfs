/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 */

#ifndef _i18n_incl_
#define _i18n_incl_

#if defined(LOCALEDIR)

#  include "gettext.h"
// make shortcut for gettext
#  define _(STR) gettext (STR)

#  include "autosprintf.h"
using gnu::autosprintf;

#else

#  define gettext(STR) (STR)
#  define gettext_noop(STR) (STR)
#  define _(STR) (STR)
#  define N_(STR) (STR)

#endif

#endif


