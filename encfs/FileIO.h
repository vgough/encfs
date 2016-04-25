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

#ifndef _FileIO_incl_
#define _FileIO_incl_

#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>

#include "Interface.h"
#include "encfs.h"

namespace encfs {

struct IORequest {
  off_t offset;

  // amount of bytes to read/write.
  int dataLen;
  unsigned char *data;

  IORequest();
};

inline IORequest::IORequest() : offset(0), dataLen(0), data(0) {}

class FileIO {
 public:
  FileIO();
  virtual ~FileIO();

  virtual Interface interface() const = 0;

  // default implementation returns 1, meaning this is not block oriented.
  virtual int blockSize() const;

  virtual void setFileName(const char *fileName) = 0;
  virtual const char *getFileName() const = 0;

  // Not sure about this -- it is specific to CipherFileIO, but the
  // alternative methods of exposing this interface aren't much nicer..
  virtual bool setIV(uint64_t iv);

  // open file for specified mode.  There is no corresponding close, so a
  // file is open until the FileIO interface is destroyed.
  virtual int open(int flags) = 0;

  // get filesystem attributes for a file
  virtual int getAttr(struct stat *stbuf) const = 0;
  virtual off_t getSize() const = 0;

  virtual ssize_t read(const IORequest &req) const = 0;
  virtual bool write(const IORequest &req) = 0;

  virtual int truncate(off_t size) = 0;

  virtual bool isWritable() const = 0;

 private:
  // not implemented..
  FileIO(const FileIO &);
  FileIO &operator=(const FileIO &);
};

}  // namespace encfs

#endif
