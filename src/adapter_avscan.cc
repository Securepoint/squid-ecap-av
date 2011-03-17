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
 *
 * -----------------------------------------------------------------
 *
 * based on the eCAP adapter samples, see: http://www.e-cap.org/
 *
 * -----------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <regex.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <cerrno>
#include <libecap/common/message.h>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>
#include <libecap/host/host.h>
#include <magic.h>

using namespace std;

static const char *socketpath  = "/tmp/clamd.sock";
static const char *magicdb     = "/usr/share/misc/magic.mgc";
static const char *skiplist    = "/etc/squid/avscanskip.conf";
static const char *description = "Securepoint eCAP antivirus adapter";

#define FUNCENTER() // cerr << "==> " << __FUNCTION__ << endl
#define DBG cerr << __FUNCTION__ << "(), "

#define TIMEOUT 5
#define ERR cerr << __FUNCTION__ << "(), "

#define TRICKLE_TIME 10	// start trickling after 30 seconds

namespace Adapter
{                               // not required, but adds clarity

using libecap::size_type;
using libecap::StatusLine;

class SkipList
{
public:
    SkipList(const char *aPath);
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
    SkipList *skipList;
    int trickle_time; // the time to wait before trickling
    magic_t mcookie;  // magic cookie

};

class Xaction:public libecap::adapter::Xaction
{
public:
    Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
    virtual ~ Xaction();

#ifndef V003
    // meta-information for the host transaction
    virtual const libecap::Area option(const libecap::Name &name) const;
    virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;
#endif

    // lifecycle
    virtual void start();
    virtual void stop();

    // adapted body transmission control
    virtual void abDiscard();
    virtual void abMake();
    virtual void abMakeMore();
    virtual void abStopMaking();

    // adapted body content extraction and consumption
    virtual libecap::Area abContent(size_type offset, size_type size);
    virtual void abContentShift(size_type size);

    // virgin body state notification
    virtual void noteVbContentDone(bool atEnd);
    virtual void noteVbContentAvailable();

    // libecap::Callable API, via libecap::host::Xaction
    virtual bool callable() const;

protected:
    void stopVb(); // stops receiving vb (if we are receiving it)
    libecap::host::Xaction * lastHostCall();      // clears hostx

private:
    libecap::shared_ptr<const Service> service; // magic database access
    libecap::host::Xaction * hostx;       // Host transaction rep
    libecap::shared_ptr <libecap::Message> adapted;

    typedef enum { opUndecided, opWaiting, opOn, opComplete, opNever } OperationState;
    typedef enum { opBuffered, opTrickle, opViralator } OperationMode;
    typedef enum { stOK, stError, stInfected } ScanState;

    OperationState receivingVb;
    OperationState sendingAb;
    OperationMode avMode;

    struct Ctx
    {
        int sockfd;
        int tempfd;
        int state;
        char *tempfn;
        char buf[BUFSIZ];
    } *Ctx;

    void openTempfile(void);

    libecap::Area ErrorPage(void);
    void avStart(void);
    void processContent(void);
    int avReadResponse(void);
    int avWriteCommand(const char *command);
    void guessMode(void);
    bool mustScan(libecap::Area area);
    void noteContentAvailable(void);

    size_type received;
    size_type processed;
    size_type contentlength;
    time_t startTime;
    time_t lastContent;
    bool trickled;
    bool senderror;
};
} // namespace Adapter

Adapter::SkipList::SkipList(const char *aPath)
{
    FUNCENTER();
    Must(aPath);
    entries = 0;

    std::string line;
    ifstream in(aPath);
    if (in.is_open()) {
        while (getline (in, line))
            add(line);
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
        /* */
    } else if (s.at(0) == '#') {
        /* */
    } else if (!(regex = new regex_t)) {
        /* */
    } else if (0 != regcomp(regex, s.c_str(), REG_EXTENDED | REG_NOSUB)) {
        /* */
    } else if (!(entry = new (struct skipListEntry))) {
        /* */
    } else {
        entry->expr = s;
        entry->preg = regex;
        entry->next = entries;
        entries = entry;
        DBG << s << ":" << sizeof(struct skipListEntry) << endl;
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
            DBG << "matched: <" << expr << ">::<" << e->expr << ">" << endl;
            return true;
        }
        e = e->next;
    }
    return false;
}

/**
 * Determines if we should scan or not.
 */
bool Adapter::Xaction::mustScan(libecap::Area area)
{
    FUNCENTER();
    if (area.size && service->skipList->ready()) {
        const char *mimetype = magic_buffer(service->mcookie, area.start, area.size);
        if (mimetype) {
            if (service->skipList->match(mimetype))
                return false;
        }
    }
    return true;
}

void Adapter::Xaction::guessMode(void)
{
    ERR << "placebo alert!" << endl;
}

static int doconnect(void)
{
    int sockfd = -1;

    if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
        ERR << "can't initialize clamd socket: " << strerror(errno) << endl;
    } else {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_LOCAL;
        strncpy(address.sun_path, socketpath, sizeof(address.sun_path));
        if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) == -1) {
            ERR << "can't connect to clamd socket: " << strerror(errno) << endl;
            close(sockfd);
            sockfd = -1;
        }
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);
        DBG << "opened clamd socket @ " << sockfd << endl;
    }
    return sockfd;
}

libecap::Area Adapter::Xaction::ErrorPage(void)
{
    std::string errmsg = "<html><head></head><body>";

    if (Ctx->state == stInfected) {
        errmsg += "<h1>Access denied!</h1>";
        errmsg += "Virus infected content found. ";
    } else {
        errmsg += "<h1>Internal error!</h1>";
        errmsg += "While scanning your request for virus infection an internal error occured!";
    }
    // errmsg += msg;
    errmsg += "</body></html>\n";
    return libecap::Area::FromTempString(errmsg);
}

void Adapter::Xaction::openTempfile(void)
{
    char fn[] = "/var/tmp/squid-ecap-XXXXXX";
    FUNCENTER();

    mkstemp(fn);
    if (-1 == (Ctx->tempfd = open(fn, O_RDWR))) {
        ERR << "can't open temp file " << fn << endl;
        Ctx->state = stError;
        return;
    }
    DBG << "opened temp file " << fn << endl;
    Ctx->tempfn = strdup(fn);
}

int Adapter::Xaction::avWriteCommand(const char *command)
{
    fd_set wfds;
    struct timeval tv;
    int n;

    FUNCENTER();

    Must(command);
    n = strlen(command) + 1;

    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    FD_ZERO(&wfds);
    FD_SET(Ctx->sockfd, &wfds);

    if (n == write(Ctx->sockfd, command, n)) {
        return n;
    } else if (n == -1 && errno != EAGAIN) {
        ERR << "write: " << strerror(errno) << endl;
    } else if (-1 == select(Ctx->sockfd + 1, &wfds, NULL, NULL, &tv)) {
        ERR << "select: " << strerror(errno) << endl;
    } else if (!(FD_ISSET(Ctx->sockfd, &wfds))) {
        ERR << "timeout @ " << Ctx->sockfd << endl;
    } else {
        // write the trailing NULL character too
        return write(Ctx->sockfd, command, n);
    }
    return -1;
}

int Adapter::Xaction::avReadResponse(void)
{
    char buf[1024];
    fd_set rfds;
    struct timeval tv;
    int n;

    FUNCENTER();

    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(Ctx->sockfd,&rfds);

    if (-1 != (n = read(Ctx->sockfd, buf, sizeof(buf)))) {
        DBG << buf << endl;
        return n;
    } else if (errno != EAGAIN) {
        ERR << "read: " << strerror(errno) << endl;
    } else if (-1 == select(Ctx->sockfd + 1, &rfds, NULL, NULL, &tv)) {
        ERR << "select; " << strerror(errno) << endl;
    } else if (!FD_ISSET(Ctx->sockfd, &rfds)) {
        ERR << "timeout @ " << Ctx->sockfd << endl;
        return -2;
    } else if (-1 == (n = read(Ctx->sockfd, buf, sizeof(buf)))) {
        ERR << "read: " << strerror(errno) << endl;
    } else {
        if(n > 7) {
            char *colon = strrchr(buf, ':');
            char *eol = buf + n;
            if(!colon) {
                Ctx->state = stError;
            } else if(!memcmp(eol - 7, " FOUND", 6)) {
                Ctx->state = stInfected;
                DBG << "infected" << endl;
            } else if(!memcmp(eol - 7, " ERROR", 6)) {
                Ctx->state = stError;
            } else {
                DBG << "nix" << endl;
            }
        }
        DBG << buf << endl;
        return n;
    }
    return -1;
}

void Adapter::Xaction::avStart(void)
{
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[]="";
    int fd;

    FUNCENTER();

    if (-1 == (Ctx->sockfd = doconnect())) {
        Ctx->state = stError;
        return;
    }

    if (-1 == avWriteCommand("zFILDES")) {
        Ctx->state = stError;
        return;
    }

    iov[0].iov_base = dummy;
    iov[0].iov_len = 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = fdbuf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = Ctx->tempfd;
    if(sendmsg(Ctx->sockfd, &msg, 0) == -1) {
        ERR << "FD send failed: " << strerror(errno) << endl;
        Ctx->state = stError;
    }
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
    os << description;
}

#ifdef V003
void Adapter::Service::configure(const Config &)
#else
void Adapter::Service::configure(const libecap::Options &cfg)
#endif
{
    FUNCENTER();
    // this service is not configurable
}

#ifdef V003
void Adapter::Service::reconfigure(const Config &)
#else
void Adapter::Service::reconfigure(const libecap::Options &cfg)
#endif
{
    FUNCENTER();
    // this service is not configurable
}

void Adapter::Service::start()
{
    FUNCENTER();
    libecap::adapter::Service::start();

    if (!(mcookie = magic_open(MAGIC_MIME_TYPE))) {
        ERR << "can't initialize magic library" << endl;
    } else if (-1 == magic_load(mcookie, magicdb)) {
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

bool Adapter::Service::wantsUrl(const char *url) const
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

Adapter::Xaction::Xaction(libecap::shared_ptr < Service > aService, libecap::host::Xaction * x):service(aService), hostx(x),
    receivingVb(opUndecided),
    sendingAb(opUndecided)
{
    received = processed = 0;
    trickled = senderror = false;
}

Adapter::Xaction::~Xaction()
{
    FUNCENTER();

    if (Ctx) {
        close(Ctx->sockfd);
        close(Ctx->tempfd);
        unlink(Ctx->tempfn);
        free(Ctx->tempfn);
        free(Ctx);
    }

    if (libecap::host::Xaction * x = hostx) {
        hostx = 0;
        x->adaptationAborted();
    }
}

#ifndef V003
const libecap::Area Adapter::Xaction::option(const libecap::Name &) const {
    return libecap::Area(); // this transaction has no meta-information
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &) const {
    // this transaction has no meta-information to pass to the visitor
}
#endif

void Adapter::Xaction::start()
{
    FUNCENTER();
    Ctx = 0;

    Must(hostx);

    if (hostx->virgin().body()) {
        receivingVb = opOn;
        hostx->vbMake();            // ask host to supply virgin body
        Ctx = (struct Ctx *)calloc(1, sizeof(struct Ctx));
        startTime = time(NULL);
    } else {
        hostx->useVirgin();
        receivingVb = opNever;
    }
}

void Adapter::Xaction::stop()
{
    FUNCENTER();
    hostx = 0;
    // the caller will delete
}

void Adapter::Xaction::abDiscard()
{
    FUNCENTER();

    Must(sendingAb == opUndecided);       // have not started yet
    sendingAb = opNever;
    stopVb();
}

void Adapter::Xaction::abMake()
{
    FUNCENTER();
    Must(sendingAb == opWaiting);       // have not yet started
    Must(hostx->virgin().body());	// that is our only source of ab content

    // we are or were receiving vb
    Must(receivingVb == opOn || receivingVb == opComplete);

    sendingAb = opOn;
}

void Adapter::Xaction::abMakeMore()
{
    FUNCENTER();
    Must(receivingVb == opOn);    // a precondition for receiving more vb
    hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking()
{
    FUNCENTER();
    sendingAb = opComplete;
    stopVb();
}

libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size)
{
    size_type sz;
    FUNCENTER();

    // required to not raise an exception on the final call with opComplete
    Must(sendingAb == opOn || sendingAb == opComplete);

    // Error?
    if (Ctx->state != stOK) {
        stopVb();
        sendingAb = opComplete;
        // Nothing written so far. We can send an error message!
        if (senderror)
            return ErrorPage();
    }

    // finished receiving?
    if (receivingVb == opComplete) {
        sz = sizeof(Ctx->buf); // use the whole buffer
        trickled = false;

        // finished sending?
        if (processed >= received) {
            sendingAb = opComplete;
            hostx->noteAbContentDone(true);
        }
    } else {
        sz = 10; // TODO: make config option
    }

    // if complete, there is nothing more to return.
    if (sendingAb == opComplete || trickled) {
        trickled = false;
        return libecap::Area::FromTempString("");
    }

    lseek(Ctx->tempfd, processed, SEEK_SET);

    if (-1 == (sz = read(Ctx->tempfd, Ctx->buf,  sz))) {
        ERR << "can't read from temp file: " << strerror(errno) << endl;
        Ctx->state = stError;
        return libecap::Area::FromTempString("");
    }

    trickled = true;
    lastContent = time(NULL);
    return libecap::Area::FromTempBuffer(Ctx->buf, sz);
}

void Adapter::Xaction::abContentShift(size_type size)
{
    Must(sendingAb == opOn);
    processed += size;
}

void Adapter::Xaction::noteContentAvailable()
{
    FUNCENTER();

    if (sendingAb == opWaiting) {
        adapted = hostx->virgin().clone();
        Must(adapted != 0);

        adapted->header().removeAny(libecap::headerContentLength);

        if (Ctx->state != stOK) {
            // last chance to indicate an error
            libecap::FirstLine *firstLine = &(adapted->firstLine());
            libecap::StatusLine *statusLine = dynamic_cast<libecap::StatusLine*>(firstLine);

            const libecap::Name name("Content-Type");
            const libecap::Header::Value value = libecap::Area::FromTempString("text/html");
            adapted->header().removeAny(name);
            adapted->header().add(name, value);

            if (statusLine)
                statusLine->statusCode(Ctx->state == stInfected ? 403 : 500);

            senderror = true;
        }

        const libecap::Name name("X-Ecap");
        const libecap::Header::Value value = libecap::Area::FromTempString(description);
        adapted->header().add(name, value);

        hostx->useAdapted(adapted);
    }
    hostx->noteAbContentAvailable();
}

// finished reading the virgin body
void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
    FUNCENTER();
    Must(Ctx);
    Must(receivingVb == opOn);

    receivingVb = opComplete;

    avStart();
    if (Ctx->state == stOK) {
        while (-2 == avReadResponse())
            ;
    }
    noteContentAvailable();
}

void Adapter::Xaction::processContent()
{
    time_t now = time(NULL);

    FUNCENTER();

    if (now < (startTime + TRICKLE_TIME)) {
        /* */
    } else if (now < (lastContent + TRICKLE_TIME)) {
        /* */
    } else {
        noteContentAvailable();
    }
}

void Adapter::Xaction::noteVbContentAvailable()
{
    FUNCENTER();
    Must(receivingVb == opOn);
    Must(Ctx);
    Must(Ctx->tempfd != -1);

    // get all virgin body
    const libecap::Area vb = hostx->vbContent(0, libecap::nsize);

    if (sendingAb == opUndecided) {
        if (mustScan(vb)) {
            openTempfile();
            // go to state waiting, hostx->useAdapted() will be called later
            // via noteContentAvailable()
            sendingAb = opWaiting;
        } else {
            // nothing to do, just send the vb
            hostx->useVirgin();
            abDiscard();
            return;
        }
    }

    lseek(Ctx->tempfd, 0, SEEK_END);

    // write body to temp file
    if (-1 == write(Ctx->tempfd, vb.start, vb.size)) {
        cerr << "can't write to temp file\n";
        Ctx->state = stError;
    }

    received += vb.size;

    // we have a copy; do not need vb any more
    hostx->vbContentShift(vb.size);

    if (sendingAb == opOn || sendingAb == opWaiting)
        processContent();
}

bool Adapter::Xaction::callable() const
{
    FUNCENTER();
    return hostx != 0;            // no point to call us if we are done
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb()
{
    FUNCENTER();
    if (receivingVb == opOn) {
        hostx->vbStopMaking();
        receivingVb = opComplete;
    } else {
        // we already got the entire body or refused it earlier
        Must(receivingVb != opUndecided);
    }
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
libecap::host::Xaction * Adapter::Xaction::lastHostCall()
{
    FUNCENTER();
    libecap::host::Xaction * x = hostx;
    Must(x);
    hostx = 0;
    return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered =
    (libecap::RegisterService(new Adapter::Service), true);