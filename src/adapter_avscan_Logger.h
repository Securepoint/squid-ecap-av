/*
 * Securepoint eCAP antivirus Adapter
 * Copyright (C) 2011, 2012 Gernot Tenchio, Securepoint GmbH, Germany.
 *
 * http://www.securepoint.de/
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * -----------------------------------------------------------------
 *
 * based on the eCAP adapter samples, see: http://www.e-cap.org/
 *
 * -----------------------------------------------------------------
 */

#include <libecap/common/log.h>
#include <iosfwd>

using libecap::ilNormal;
using libecap::ilCritical;
using libecap::flXaction;
using libecap::flApplication;

class Logger {
    public:
	Logger(const libecap::LogVerbosity lv);
	~Logger();
	template <class T>
	const Logger &operator <<(const T &msg) const {
	    if (out)
		*out << msg;
	    return *this;
	}
    private:
	std::ostream *out;
};
