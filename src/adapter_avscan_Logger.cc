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

#include "adapter_avscan_Logger.h"
#include <libecap/common/registry.h>
#include <libecap/host/host.h>
#include <iostream>

Logger::Logger(const libecap::LogVerbosity lv):
    out(libecap::MyHost().openDebug(lv)) {
}

Logger::~Logger() {
    if (out)
	libecap::MyHost().closeDebug(out);
}
