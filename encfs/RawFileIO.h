/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
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

#ifndef _RawFileIO_incl_
#define _RawFileIO_incl_

#include <string>
#include <sys/types.h>

#include "FileIO.h"
#include "Interface.h"

namespace encfs {

class RawFileIO : public FileIO {
 public:
  RawFileIO();
  RawFileIO(const std::string &fileName);
  virtual ~RawFileIO();

  virtual Interface interface() const;

  virtual void setFileName(const char *fileName);
  virtual const char *getFileName() const;

  virtual int open(int flags);

  virtual int getAttr(struct stat *stbuf) const;
  virtual off_t getSize() const;

  virtual ssize_t read(const IORequest &req) const;
  virtual bool write(const IORequest &req);

  virtual int truncate(off_t size);

  virtual bool isWritable() const;

 protected:
  std::string name;

  bool knownSize;
  off_t fileSize;

  int fd;
  int oldfd;
  bool canWrite;
};

}  // namespace encfs

#endif
