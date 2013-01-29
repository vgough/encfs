
/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2012 Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.  
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "fs/MemFileIO.h"

#include "base/Error.h"

#include <glog/logging.h>

static Interface MemFileIO_iface = makeInterface("FileIO/Mem", 1, 0, 0);

MemFileIO* NewMemFileIO(const Interface& iface) {
  (void)iface;
  return new MemFileIO(0);
}

MemFileIO::MemFileIO(int size) 
    : writable(false) {
  buf.resize(size);
}

MemFileIO::~MemFileIO() {
}

Interface MemFileIO::interface() const {
  return MemFileIO_iface;
}

void MemFileIO::setFileName(const char *name) {
  this->name = name;
}

const char *MemFileIO::getFileName() const {
  return name.c_str();
}

int MemFileIO::open(int flags) {
  bool requestWrite = ((flags & O_RDWR) || (flags & O_WRONLY));

  writable = writable || requestWrite;
  LOG(ERROR) << "returning fake file descriptor";
  return 0;
}

int MemFileIO::getAttr(struct stat* stbuf) const {
  stbuf->st_size = buf.size();
  return 0;
}

off_t MemFileIO::getSize() const {
  return buf.size();
}

ssize_t MemFileIO::read(const IORequest& req) const {
  rAssert(req.offset >= 0);

  int len = req.dataLen;
  if (req.offset + req.dataLen > getSize()) {
    len = getSize() - req.offset;
  }
  if (len < 0) {
    len = 0;
  }

  memcpy(req.data, &buf[req.offset], len);
  return len;
}

bool MemFileIO::write(const IORequest& req) {
  rAssert(req.offset >= 0);
  if (req.offset + req.dataLen > getSize()) {
    truncate(req.offset + req.dataLen);
  }
  rAssert(req.offset + req.dataLen <= getSize());

  memcpy(&buf[req.offset], req.data, req.dataLen);
  return true;
}

int MemFileIO::truncate(off_t size) {
  buf.resize(size);
  return 0;
}

bool MemFileIO::isWritable() const {
  return writable;
}

