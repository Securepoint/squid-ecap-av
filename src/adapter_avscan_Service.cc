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

//#include <stdlib.h>   // atoi()

#include <fstream>
#include <iostream>
#include <algorithm>
#include <string>
#include <cerrno>
#include <climits>
#include <cstring>
#include <list>
#include <map>

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
#include "adapter_avscan_Logger.h"
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
	Logger(ilCritical|flApplication) << "can't open " << aPath;
    }
}

Adapter::SkipList::~SkipList()
{
    if (NULL == entries) {
	/* nothing to free */
    } else {
	struct skipListEntry *entry = entries;
	while (entry) {
	    struct skipListEntry *next = entry->next;
	    regfree(entry->preg);
	    delete(entry);
	    entry = next;
	}
    }
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
    } else if (0 != regcomp(regex, s.c_str(), REG_EXTENDED | REG_NOSUB | REG_ICASE)) {
	Logger(ilCritical|flApplication) << "invalid regular expression @ " << linenumber;
    } else if (!(entry = new (struct skipListEntry))) {
        /* oom */
    } else {
        entry->preg = regex;
        entry->next = entries;
        entries = entry;
        return;
    }

    if (regex)
        regfree(regex);
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

Adapter::AdditionalOptions::AdditionalOptions(std::string path)
{
    constexpr char key_value_translate[] = "^([[:alpha:]]+)[ \t]*(:)[ \t]*([[:print:]]+)";
    std::string line;
    regex_t re;
    regmatch_t rm[5];

    ifstream in(path.c_str());

    if (in.is_open()) {
        regcomp(&re, key_value_translate, REG_EXTENDED);
        while (getline (in, line)) {
            std::string key, val;
            // first look for translate pairs 'option : translateToLogKey'
            if (regexec(&re, line.c_str(), 5, rm, 0)) {
                continue;
            }
            key = line.substr(rm[1].rm_so, rm[1].rm_eo - rm[1].rm_so);
            val = line.substr(rm[3].rm_so, rm[3].rm_eo - rm[3].rm_so);
            translateKeys[val] = key;
            additionalKeys.push_back(key);
        }
        regfree(&re);
    } else {
        Logger(ilCritical|flXaction) << "error opening option config file " << path;
    }
}

const std::list<std::string> &
Adapter::AdditionalOptions::getAdditionalKeys()
{
    return additionalKeys;
}

const std::map<std::string, std::string> &
Adapter::AdditionalOptions::getTranslateKeys()
{
    return translateKeys;
}

Adapter::Service::Service() :
        skipList(NULL),
        blockList(NULL),
        trickletime(30),
        readtimeout(TIMEOUT * 2),
        writetimeout(TIMEOUT),
        tricklesize(10),
        maxscansize(0),
        mcookie(NULL),
        options(NULL)
{}

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

static libecap::size_type parseunit(std::string s, std::string name)
{
    char *unit;
    libecap::size_type size, calculated;

    if (ULONG_MAX == (size = strtoul(s.c_str(), &unit, 10))) {
	Logger(ilCritical|flApplication) << name << " value '" << s << "' to large, using " << size << " instead";
	return size;
    }

    // skip spaces if any
    while (' ' == *unit) unit++;
    if (0 == strncmp(unit, "KB", 2))
	calculated = size * 1024;
    else if (0 == strncmp(unit, "MB", 2))
	calculated = size * 1024 * 1024;
    else
	calculated = size;

    // check for integer overflow
    if (calculated < size) {
	Logger(ilCritical|flApplication) << "integer overflow, ignoring unit, using " << size << " instead";
	calculated = size;
    }
    return calculated;
}

void Adapter::Service::readconfig(std::string aPath)
{
    FUNCENTER();
    Must(aPath != "");

    constexpr char key_value_line[] = "^([[:alpha:]]+)([ \t=]*)([[:print:]]+)";
    std::string line;
    regex_t re;
    regmatch_t rm[5];

    ifstream in(aPath.c_str());
    if (in.is_open()) {
        regcomp(&re, key_value_line, REG_EXTENDED);
        while (getline (in, line)) {
            std::string key, val;

            if (regexec(&re, line.c_str(), 5, rm, 0)) {
                continue;
            }

            // key = value
            key = line.substr(rm[1].rm_so, rm[1].rm_eo - rm[1].rm_so);
            val = line.substr(rm[3].rm_so, rm[3].rm_eo - rm[3].rm_so);

            if (key == "maxscansize") {
                maxscansize = parseunit(val, "maxscansize");
            } else if (key == "trickletime") {
                trickletime = strtoul(val.c_str(), NULL, 10);
            } else if (key == "tricklesize") {
                if (0 >= (tricklesize = atoi(val.c_str())))
                    tricklesize = 1;
            } else if (key == "avdsocket") {
                avdsocket = val;
            } else if (key == "magicdb") {
                magicdb = val;
            } else if (key == "tempdir") {
                tempdir = val;
            } else if (key == "skiplist") {
                skiplist = val;
            } else if (key == "blocklist") {
                blocklist = val;
            } else if (key == "readtimeout") {
                if (0 >= (readtimeout = atoi(val.c_str())))
                    readtimeout = TIMEOUT * 2;
            } else if (key == "writetimeout") {
                if (0 >= (writetimeout = atoi(val.c_str())))
                    writetimeout = TIMEOUT;
            } else if (key == "optionlist") {
                optionlist = val;
            }
        }
        regfree(&re);
        in.close();
    } else {
	Logger(ilCritical|flApplication) << "can't open " << aPath;
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

    avdsocket = "/tmp/clamd.sock";
    magicdb     = "/usr/share/misc/magic.mgc";
    skiplist    = "/etc/squid/ecap_adapter_av.skip";
    blocklist   = "/etc/squid/ecap_adapter_av.block";
    tempdir     = "/var/tmp";

    readconfig(configfn);

    LOG_DBG("using avdsocket=%s", avdsocket.c_str());
/* Some old versions of libmagic don't support MAGIC_MIME_TYPE.
 * But hey, if we have squid-3.1 we should probably also have an
 * actual version of libmagic. Anyhow, use MAGIC_MIME instead.
 */
#ifndef MAGIC_MIME_TYPE
    if (!(mcookie = magic_open(MAGIC_MIME)))
#else
    if (!(mcookie = magic_open(MAGIC_MIME_TYPE)))
#endif
    {
	Logger(ilCritical|flApplication) << "can't initialize magic library, skiplists won't work!";
    } else if (-1 == magic_load(mcookie, magicdb.c_str())) {
	Logger(ilCritical|flApplication) << "can't load magic database, skiplists won't work!";
        magic_close(mcookie);
        mcookie = NULL;
    }
    skipList = new Adapter::SkipList(skiplist);
    blockList = new Adapter::SkipList(blocklist);
    if (optionlist.length() > 0) {
        options = new Adapter::AdditionalOptions(optionlist);
    }
    Logger(flApplication) << ADAPTERNAME << " started";
}

void Adapter::Service::stop()
{
    FUNCENTER();

    if (mcookie)
        magic_close(mcookie);
    if (skipList) {
        delete(skipList);
        skipList = NULL;
    }
    if (blockList) {
        delete(blockList);
        blockList = NULL;
    }
    if (options) {
        delete(options);
        options = NULL;
    }

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

#ifdef V100
Adapter::Service::MadeXactionPointer
Adapter::Service::makeXaction(libecap::host::Xaction * hostx)
{
    FUNCENTER();
    return Service::MadeXactionPointer(new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx));
}

// create the adapter and register with libecap to reach the host application
static bool Registered =
    libecap::RegisterVersionedService(new Adapter::Service());
#else
libecap::adapter::Xaction *
Adapter::Service::makeXaction(libecap::host::Xaction * hostx)
{
    FUNCENTER();
    return new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx);
}

// create the adapter and register with libecap to reach the host application
static const bool Registered =
    (libecap::RegisterService(new Adapter::Service), true);
#endif
