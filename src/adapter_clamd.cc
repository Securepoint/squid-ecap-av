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
#include <fcntl.h>
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

using namespace std;

const char *socketpath = "/tmp/clamd.sock";

#define FUNCENTER() // cerr << "==> " << __FUNCTION__ << endl
#define DBG cerr << __FUNCTION__ << ", "

#define TIMEOUT 5
#define ERR cerr << __FUNCTION__ << ", "

#define TRICKLE_TIME 30	// start trickling after 30 seconds

namespace Adapter
{                               // not required, but adds clarity

using libecap::size_type;
using libecap::StatusLine;

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

    int trickle_time; // the time to wait before trickling
    std::string socketpath;
};

class Xaction:public libecap::adapter::Xaction
{
public:
#ifdef V003
    Xaction(libecap::host::Xaction * x);
    virtual ~ Xaction();
#else
    Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
    virtual ~ Xaction();

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
#ifndef V003
    libecap::shared_ptr<const Service> service; // configuration access
#endif
    libecap::host::Xaction * hostx;       // Host transaction rep
    libecap::shared_ptr <libecap::Message> adapted;
    typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
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

    void sendErrorPage(void);
    void avStart(void);
    void processContent(void);
    int avReadResponse(void);
    int avWriteCommand(const char *command);
    void guessMode(void);
    bool mustScan(libecap::Area area);

    size_type received;
    size_type processed;
    size_type contentlength;
    time_t startTime;
    time_t lastContent;
    bool trickled;
};
} // namespace Adapter

/**
 * Determines if we should scan or not.
 */
bool Adapter::Xaction::mustScan(libecap::Area area)
{
    ERR << "Placebo alert! Place file detection code here! area.size " << area.size << " area.start[0] " << area.start[0] << endl;
    if (area.size) {
        if (area.start[0] == '<')
            return false;
        else
            return true;
    }
    return true;
}

void Adapter::Xaction::guessMode(void)
{
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

void Adapter::Xaction::sendErrorPage(void)
{
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
    os << "Securepoint eCAP antivirus adapter";
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
    // custom code would go here, but this service does not have one
}

void Adapter::Service::stop()
{
    FUNCENTER();
    // custom code would go here, but this service does not have one
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
#ifdef V003
    return new Adapter::Xaction(hostx);
#else
    return new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx);
#endif
}

#ifdef V003
Adapter::Xaction::Xaction(libecap::host::Xaction * x):hostx(x),
#else
Adapter::Xaction::Xaction(libecap::shared_ptr < Service > aService, libecap::host::Xaction * x):service(aService), hostx(x),
#endif
    receivingVb(opUndecided),
    sendingAb(opUndecided)
{
    received = processed = 0;
    trickled = false;
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
    } else {
        receivingVb = opNever;
    }

    adapted = hostx->virgin().clone();
    Must(adapted != 0);

    // try to read the Content-Length header
    if (adapted->header().hasAny(libecap::headerContentLength)) {
        const libecap::Header::Value value =
            adapted->header().value(libecap::headerContentLength);
        if (value.size > 0) {
            contentlength = strtol(value.start, NULL, 10);
            cerr << "Content-Length: " << value.start << endl;
        }
    }

    // Add informational response header
    static const libecap::Name name("X-Ecap");
    const libecap::Header::Value value =
        libecap::Area::FromTempString("Securepoint eCAP clamd Adapter");
    adapted->header().add(name, value);

    if (!adapted->body()) {
        cerr << "Xaction::start: Nothing to send here!" << endl;
        sendingAb = opNever;        // there is nothing to send
        lastHostCall()->useAdapted(adapted);
    } else {
        // remember to delete the ContentLength header if are in viralator mode
        Ctx = (struct Ctx *)calloc(1, sizeof(struct Ctx));
        startTime = time(NULL);
        adapted->header().removeAny(libecap::headerContentLength);
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
    Must(sendingAb == opUndecided);       // have not yet started or decided not to send
    Must(hostx->virgin().body());		// that is our only source of ab content

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

    // required to not raise an exception on the final call with opComplete
    Must(sendingAb == opOn || sendingAb == opComplete);

    // Error?
    if (Ctx->state == stError && !processed) {
      ERR << "should send an errorpage!" << endl;
      stopVb();
      sendingAb = opComplete;
      hostx->noteAbContentDone(true);
      return libecap::Area::FromTempString("Error");
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

    DBG << " sending " << sz << endl;
    trickled = true;
    lastContent = time(NULL);
    return libecap::Area::FromTempBuffer(Ctx->buf, sz);
}

void Adapter::Xaction::abContentShift(size_type size)
{
    Must(sendingAb == opOn);
    processed += size;
    DBG << "got: " << size << ", processed so far: " << processed << "/" << received << " bytes\n";
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
    hostx->noteAbContentAvailable();
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
        hostx->noteAbContentAvailable();
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
            hostx->useAdapted(adapted);
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
        return;
    }

    received += vb.size;

    // we have a copy; do not need vb any more
    hostx->vbContentShift(vb.size);

    if (sendingAb == opOn)
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
// TODO: replace with hostx-independent "done" method
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
