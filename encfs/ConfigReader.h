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

#ifndef _ConfigReader_incl_
#define _ConfigReader_incl_

#include <map>
#include <string>

#include "ConfigVar.h"

namespace encfs {

/*
    handles Configuration load / store for Encfs filesystems.

    loading existing config file example:

    ConfigReader cfg;
    cfg.load( filesystemConfigFile );

    Interface iface;
    cfg["cipher"] >> iface;


    creating new config example:

    ConfigReader cfg;
    cfg["cipher"] << cipher->interface();
*/
class ConfigReader {
 public:
  ConfigReader();
  ~ConfigReader();

  bool load(const char *fileName);
  bool save(const char *fileName) const;

  ConfigVar toVar() const;
  bool loadFromVar(ConfigVar &var);

  ConfigVar operator[](const std::string &varName) const;
  ConfigVar &operator[](const std::string &varName);

 private:
  std::map<std::string, ConfigVar> vars;
};

}  // namespace encfs

#endif
