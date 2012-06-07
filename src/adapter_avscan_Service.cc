/*
 * Securepoint eCAP clamd Adapter
 * Copyright (C) 2011 Gernot Tenchio, Securepoint GmbH, Germany.
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

//#include <stdlib.h>   // atoi()

#include <fstream>
#include <iostream>
#include <algorithm>
#include <string>
#include <cerrno>

#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>
#include <libecap/host/host.h>

#include "adapter_avscan_Service.h"
#include "adapter_avscan_Xaction.h"
#include "adapter_avscan.h"

using namespace std;

static const char *configfn = "/etc/squid/ecap_adapter_av.conf";

Adapter::SkipList::SkipList(std::string aPath)
{
    FUNCENTER();
    Must(aPath != "");
    entries = 0;
    linenumber = 0;

    std::string line;
    ifstream in(aPath.c_str());
    if (in.is_open()) {
        while (getline (in, line)) {
            linenumber++;
            add(line);
        }
        in.close();
    } else {
        ERR << "can't open " << aPath << endl;
    }
}

Adapter::SkipList::~SkipList()
{
    ERR << "placebo alert!" << endl;
}

void Adapter::SkipList::add(std::string s)
{
    regex_t *regex = NULL;
    struct skipListEntry *entry;

    if (std::string::npos == s.find_first_not_of(" \t\r\n")) {
        /* empty line */
    } else if (s.at(0) == '#') {
        /* comment */
    } else if (!(regex = new regex_t)) {
        /* oom */
    } else if (0 != regcomp(regex, s.c_str(), REG_EXTENDED | REG_NOSUB)) {
        ERR << "invalid regular expression @ " << linenumber << endl;
    } else if (!(entry = new (struct skipListEntry))) {
        /* oom */
    } else {
        entry->expr = s;
        entry->preg = regex;
        entry->next = entries;
        entries = entry;
        return;
    }

    delete(regex);
}

bool Adapter::SkipList::ready(void)
{
    FUNCENTER();
    return entries != 0;
}

bool Adapter::SkipList::match(const char *expr)
{
    FUNCENTER();
    struct skipListEntry *e = entries;
    while (e) {
        if (0 == regexec(e->preg, expr, 0, 0, 0)) {
            return true;
        }
        e = e->next;
    }
    return false;
}

std::string Adapter::Service::uri() const
{
    FUNCENTER();
    return "ecap://www.securepoint.de/ecap_av";
}

std::string Adapter::Service::tag() const
{
    FUNCENTER();
    return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream & os) const
{
    FUNCENTER();
    os << ADAPTERNAME;
}

static ScanMethod parseMeth(std::string aMethod)
{
    ScanMethod meth = methFildes;

    transform(aMethod.begin(), aMethod.end(), aMethod.begin(), ::tolower);

    if (aMethod == "fildes") {
	/* */
    } else if (aMethod == "instream") {
	meth = methInstream;
    } else {
        ERR << "invalid scan method, falling back to FILDES" << endl;
    }
    return meth;
}

void Adapter::Service::readconfig(std::string aPath)
{
    FUNCENTER();
    Must(aPath != "");

    std::string line;
    regex_t re;
    regmatch_t rm[5];

    regcomp(&re, "^([[:alpha:]]+)([ \t=]*)([[:print:]]+)", REG_EXTENDED);
    ifstream in(aPath.c_str());
    if (in.is_open()) {
        while (getline (in, line)) {
            std::string key, val;

            if (regexec(&re, line.c_str(), 5, rm, 0))
                continue;

            key = line.substr(rm[1].rm_so, rm[1].rm_eo - rm[1].rm_so);
            val = line.substr(rm[3].rm_so, rm[3].rm_eo - rm[3].rm_so);

            if (key == "maxscansize") {
                maxscansize = strtoul(val.c_str(), NULL, 10);
            } else if (key == "trickletime") {
                trickletime = strtoul(val.c_str(), NULL, 10);
            } else if (key == "tricklesize") {
                if (0 >= (tricklesize = atoi(val.c_str())))
                    tricklesize = 1;
            } else if (key == "clamdsocket") {
                clamdsocket = val;
            } else if (key == "magicdb") {
                magicdb = val;
            } else if (key == "tempdir") {
                tempdir = val;
            } else if (key == "skiplist") {
                skiplist = val;
            } else if (key == "method") {
		method = parseMeth(val);
	    }
        }
        in.close();
    } else {
        ERR << "can't open " << aPath << endl;
    }
}

#ifdef V003
void Adapter::Service::configure(UNUSED const Config &)
#else
void Adapter::Service::configure(UNUSED const libecap::Options &cfg)
#endif
{
    FUNCENTER();
    // this service is not configurable
}

#ifdef V003
void Adapter::Service::reconfigure(UNUSED const Config &)
#else
void Adapter::Service::reconfigure(UNUSED const libecap::Options &cfg)
#endif
{
    FUNCENTER();
    // this service is not configurable
}

void Adapter::Service::start()
{
    FUNCENTER();
    libecap::adapter::Service::start();

    clamdsocket = "/tmp/clamd.sock";
    magicdb     = "/usr/share/misc/magic.mgc";
    skiplist    = "/etc/squid/ecap_adapter_av.skip";
    tempdir     = "/var/tmp";
    maxscansize = 0;
    trickletime = 30;
    tricklesize = 10;
    method      = methFildes;

    readconfig(configfn);

    if (!(mcookie = magic_open(MAGIC_MIME_TYPE))) {
        ERR << "can't initialize magic library" << endl;
    } else if (-1 == magic_load(mcookie, magicdb.c_str())) {
        ERR << "can't initialize magic database" << endl;
        magic_close(mcookie);
        mcookie = NULL;
    }
    skipList = new Adapter::SkipList(skiplist);
}

void Adapter::Service::stop()
{
    FUNCENTER();

    if (mcookie)
        magic_close(mcookie);
    if (skipList)
        delete(skipList);

    libecap::adapter::Service::stop();
}

void Adapter::Service::retire()
{
    FUNCENTER();
    // custom code would go here, but this service does not have one
    libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(UNUSED const char *url) const
{
    FUNCENTER();
    return true;                  // no-op is applied to all messages
}

libecap::adapter::Xaction *
Adapter::Service::makeXaction(libecap::host::Xaction * hostx)
{
    FUNCENTER();
    return new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx);
}

// create the adapter and register with libecap to reach the host application
static const bool Registered =
    (libecap::RegisterService(new Adapter::Service), true);
