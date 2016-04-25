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

#ifndef _Range_incl_
#define _Range_incl_

namespace encfs {

class Range {
  int minVal;
  int maxVal;
  int increment;

 public:
  Range();
  Range(int minMax);
  Range(int min, int max, int increment);

  bool allowed(int value) const;

  int closest(int value) const;

  int min() const;
  int max() const;
  int inc() const;
};

inline Range::Range(int minMax) {
  this->minVal = minMax;
  this->maxVal = minMax;
  this->increment = 1;
}

inline Range::Range(int min_, int max_, int increment_) {
  this->minVal = min_;
  this->maxVal = max_;
  this->increment = increment_;
  if (increment == 0) this->increment = 1;
}

inline Range::Range() : minVal(-1), maxVal(-1), increment(1) {}

inline bool Range::allowed(int value) const {
  if (value >= minVal && value <= maxVal) {
    int tmp = value - minVal;
    if ((tmp % increment) == 0) return true;
  }
  return false;
}

inline int Range::closest(int value) const {
  if (allowed(value))
    return value;
  else if (value < minVal)
    return minVal;
  else if (value > maxVal)
    return maxVal;

  // must be inbetween but not matched with increment
  int tmp = value - minVal;
  // try rounding to the nearest increment..
  tmp += (increment >> 1);
  tmp -= (tmp % increment);

  return closest(value + tmp);
}

inline int Range::min() const { return minVal; }

inline int Range::max() const { return maxVal; }

inline int Range::inc() const { return increment; }

}  // namespace encfs

#endif
