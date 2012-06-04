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

#include <libecap/adapter/service.h>
#include <magic.h>
#include <regex.h>

namespace Adapter
{

using libecap::size_type;

class SkipList
{
public:
    SkipList(std::string aPath);
    virtual ~SkipList();
    bool match(const char *expr);
    bool ready();
private:
    void add(std::string s);
    struct skipListEntry {
        std::string expr;
        regex_t *preg;
        struct skipListEntry *next;
    } *entries;
    int linenumber;
};

class Service:public libecap::adapter::Service
{

public:
    // About
    virtual std::string uri() const;    // unique across all vendors
    virtual std::string tag() const;    // changes with version and config
    virtual void describe(std::ostream & os) const;     // free-format info

    // Configuration
#ifdef V003
    virtual void configure(const Config & cfg);
    virtual void reconfigure(const Config & cfg);
#else
    virtual void configure(const libecap::Options &cfg);
    virtual void reconfigure(const libecap::Options &cfg);
#endif
    // Lifecycle
    virtual void start();       // expect makeXaction() calls
    virtual void stop();        // no more makeXaction() calls until start()
    virtual void retire();      // no more makeXaction() calls

    // Scope
    virtual bool wantsUrl(const char *url) const;

    // Work
    virtual libecap::adapter::Xaction * makeXaction(libecap::host::Xaction * hostx);

    // Config
    SkipList *skipList;      // list of mimetypes to exclude from scanning
    std::string clamdsocket; // path to clamd socket
    std::string magicdb;     // magic database location
    std::string skiplist;    // skiplist file
    std::string tempdir;     // directory to store temp files in
    time_t trickletime;   // the time to wait before trickling
    size_type tricklesize;   // number of bytes to send
    size_type maxscansize;   // skip scanning bodies greater than maxscansize
    magic_t mcookie;         // magic cookie

private:
    void readconfig(std::string aPath);

};

}
