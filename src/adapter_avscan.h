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
 */

#ifndef _ADAPTER_AVSCAN_H
#define _ADAPTER_AVSCAN_H 1

#define ADAPTERNAME "Securepoint eCAP antivirus adapter"

#ifdef __GNUC__
  #define UNUSED __attribute__((__unused__))
#else
  #define UNUSED
#endif

#ifdef DEBUG
  #define FUNCENTER() cerr << "==> " << __FUNCTION__ << endl
  #define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
  #define FUNCENTER()
  #define DEBUG(...)
#endif

#define ERR cerr << __FUNCTION__ << "(), "

#define TIMEOUT 5
typedef enum { engineAuto, engineClamav, engineCommtouch } ScanEngine;

#endif
