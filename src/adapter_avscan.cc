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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>	// uint32_t
#include <arpa/inet.h>	// htonl

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <cerrno>

#include <libecap/common/message.h>
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

libecap::Area Adapter::Xaction::ErrorPage(void)
{
    std::string errmsg = "<html><head></head><body>";
    if (Ctx->status == stInfected) {
        errmsg += "<h1>Access denied!</h1>";
        errmsg += "You've tried to upload/download a file that contains the virus ";
    } else if (Ctx->status == stBlocked) {
        errmsg += "<h1>Access denied!</h1>";
    } else {
        errmsg += "<h1>Internal error!</h1>";
        errmsg += "While scanning your request for virus infection an internal error occured!";
    }
    errmsg += "<blockquote>" + statusString + ".</blockquote>";
    errmsg += "</body></html>\n";
    return libecap::Area::FromTempString(errmsg);
}

void Adapter::Xaction::cleanup(void)
{
    if (Ctx) {
        if (Ctx->status == stInfected)
            Logger(ilCritical|flXaction) << "INFECTED, " << statusString;
        else if (Ctx->status == stBlocked)
            Logger(ilCritical|flXaction) << "BLOCKED, " << statusString;
        else if (statusString != "OK")
            Logger(ilCritical|flXaction) << statusString;

        if (-1 != Ctx->sockfd)
            close(Ctx->sockfd);

        if (-1 != Ctx->tempfd)
            close(Ctx->tempfd);

        free(Ctx);
        Ctx = NULL;
    }
}

/**
 * Determines if we should scan or not.
 */
void Adapter::Xaction::checkFileType(libecap::Area area)
{
    FUNCENTER();
    mustscan = true;

    if (area.size && service->skipList->ready()) {
        const char *mimetype = magic_buffer(service->mcookie, area.start, area.size);
        if (mimetype) {
            if (service->skipList->match(mimetype))
                mustscan = false;

	    if (service->blockList->match(mimetype)) {
		statusString = "bad mime type detected: ";
		statusString += mimetype;
		Ctx->status = stBlocked;
                mustscan = false;
	    }
        }
    }
    if (bypass)
	mustscan = false;
}

void Adapter::Xaction::openTempfile(void)
{
    char fn[PATH_MAX];
    FUNCENTER();

    snprintf(fn, PATH_MAX - 1, "%s/squid-ecap-XXXXXX", service->tempdir.c_str());
    if (-1 == (Ctx->tempfd = mkstemp((char *)fn))) {
        statusString = "can't open temp file: ";
        statusString += strerror(errno);
        Ctx->status = stError;
        return;
    }
    unlink(fn);
}

int Adapter::Xaction::avWriteCommand(const char *command)
{
    fd_set wfds;
    struct timeval tv;
    int n;

    FUNCENTER();

    Must(command);
    n = strlen(command) + 1;

    tv.tv_sec = service->writetimeout;
    tv.tv_usec = 0;

    FD_ZERO(&wfds);
    FD_SET(Ctx->sockfd, &wfds);

    if (n == write(Ctx->sockfd, command, n)) {
        return n;
    } else if (n == -1 && errno != EAGAIN) {
        statusString = "can't write to AV-daemon socket: ";
        statusString += strerror(errno);
    } else if (-1 == select(Ctx->sockfd + 1, NULL, &wfds, NULL, &tv)) {
        statusString = "AV-daemon (w)socket select failed: ";
        statusString += strerror(errno);
    } else if (!(FD_ISSET(Ctx->sockfd, &wfds))) {
        statusString = "AV-daemon (w)socket timeout";
    } else {
        // write the trailing NULL character too
        return write(Ctx->sockfd, command, n);
    }
    return -1;
}

int Adapter::Xaction::avReadResponse(void)
{
    fd_set rfds;
    struct timeval tv;
    int n, off = 0;

    FUNCENTER();

    tv.tv_sec = service->readtimeout;
    tv.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(Ctx->sockfd,&rfds);

    while (1) {
	n = -1;
	if (-1 == select(Ctx->sockfd + 1, &rfds, NULL, NULL, &tv)) {
	    statusString = "AV-daemon (r)socket select failed: ";
	    statusString += strerror(errno);
	} else if (!FD_ISSET(Ctx->sockfd, &rfds)) {
	    statusString = "AV-daemon (r)socket timeout";
	    n = -2;
	} else if (-1 == (n = read(Ctx->sockfd, Ctx->avbuf + off, sizeof(Ctx->avbuf) - off))) {
	    statusString = "can't read from AV-daemon socket: ";
	    statusString += strerror(errno);
	} else if ((int)sizeof(Ctx->avbuf) <= (off += n)) {
	    statusString = "AV-buffer to small";
	    n = -1;
	} else if (Ctx->avbuf[off - 1] != '\0') {
	    continue;
	}
	break;
    }
    return n;
}

void Adapter::Xaction::avStartCommtouch(void)
{
    FUNCENTER();

    if (-1 == avWriteCommand("zINSTREAM")) {
        Ctx->status = stError;
    } else if (0 > avReadResponse()) {
        Ctx->status = stError;
    } else if (strcmp(Ctx->avbuf, "OK SEND_DATA")) {
        Ctx->status = stError;
    } else {
	avWriteStream();
    }
}

// Returns:
//  -1: Error
//  -2: Timeout reading from AV-socket
//   positive number: scan succeeded, status is reported via Ctx->status
int Adapter::Xaction::avScanResultCommtouch(void)
{
    // 31:OK INFECTED 0xce24df2e EICAR_Test_File|Virus
    //
    // DAEMON_STATUS  :: OK
    // SCANNER_STATUS :: INFECTED
    // OBJECT         :: 0xce24df2e, CRC32 checksum of the stream
    // MESSAGE        :: EICAR_Test_File|Virus

    char *colon;
    int n = avReadResponse();

    if (n <= 0) {
	/* */
    } else if (NULL == (colon = strchr(Ctx->avbuf, ':'))) {
	Ctx->status = stError;
	statusString = "garbled response from AV-daemon";
    } else {
	istringstream iss(colon + 1);
	string sstat, dstat, object;

	iss >> dstat >> sstat >> object >> statusString;

	// check daemon status
	if (dstat == "FAIL") {
	    Ctx->status = stError;
	} else {
	    // now check scanner status
	    if (sstat == "CLEAN") {
		/* */
	    } else if (sstat == "INFECTED") {
		statusString.resize(statusString.rfind("|"));
		Ctx->status = stInfected;
	    }
	}
    }
    return n;
}

void Adapter::Xaction::avStartClamav(void)
{
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[]="";

    FUNCENTER();
    if (-1 == avWriteCommand("zFILDES")) {
        Ctx->status = stError;
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
        statusString = "FD send failed: ";
        statusString += strerror(errno);
        Ctx->status = stError;
    }
}

int Adapter::Xaction::avScanResultClamav(void)
{
    // Clamav:
    //  'fd[10]: Eicar-Test-Signature FOUND'
    //  'fd[10]: OK'
    // Commtouch (broken UseClamdResponseFormat)
    //  ': EICAR_Test_File|Virus FOUND'
    //	' OK'

    FUNCENTER();

    int n = avReadResponse();

    if (n > 0) {
	char *start;
	char *eol = Ctx->avbuf + n;

	if (NULL == (start = strrchr(Ctx->avbuf, ':')))
	    start = Ctx->avbuf;
	else
	    start += 2;

	if(!memcmp(eol - 4, " OK", 3)) {
	    /* :-) */
	} else if(!memcmp(eol - 7, " FOUND", 6)) {
	    Ctx->status = stInfected;
	    statusString = start;
	    statusString.resize(statusString.size() - 6);
	} else if(!memcmp(eol - 7, " ERROR", 6)) {
	    Ctx->status = stError;
	    statusString = start;
	    statusString.resize(statusString.size() - 6);
	} else {
	    Ctx->status = stError;
	    statusString = "garbled response from AV-daemon";
	}
    }
    return n;
}

// Create a socket and connect it to aPath. If the connect() succeeds
// set the so created socket to nonblocking mode. If aPath.length()
// exceeds sizeof(address.sun_path) connect() returns ENOENT.
static int doconnect(std::string aPath)
{
    int sockfd = -1;

    if (-1 != (sockfd = socket(AF_LOCAL, SOCK_STREAM, 0))) {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_LOCAL;
        strncpy(address.sun_path, aPath.c_str(), sizeof(address.sun_path));
        if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) == -1) {
            close(sockfd);
            sockfd = -1;
        }
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);
    }
    return sockfd;
}

int Adapter::Xaction::avScanResult(void)
{
    int ret = -1;
    if (engine == engineCommtouch) {
	ret = avScanResultCommtouch();
    } else {
	ret = avScanResultClamav();
    }
    return ret;
}

void Adapter::Xaction::avStart(void)
{

    FUNCENTER();

    if (engine == engineAuto)
	avCheckVersion();

    if (stError == Ctx->status) {
	/* */
    } else if (-1 == (Ctx->sockfd = doconnect(service->avdsocket))) {
        Ctx->status = stError;
    } else if (engine == engineCommtouch) {
	avStartCommtouch();
    } else {
	avStartClamav();
    }

}

int Adapter::Xaction::avWriteChunk(char *buf, ssize_t len)
{
    struct iovec iov[2];
    uint32_t chunksize = htonl((uint32_t)len);
    int n;

    FUNCENTER();
    iov[0].iov_len  = 4;
    iov[0].iov_base = &chunksize;
    iov[1].iov_len  = len;
    iov[1].iov_base = buf;

    while (-1 == (n = writev(Ctx->sockfd, iov, 2)) && errno == EAGAIN);

    return n;
}

void Adapter::Xaction::avWriteStream(void)
{
    char buf[BUFSIZ];
    ssize_t len;

    FUNCENTER();
    // Set offset to the beginning of the file
    if (-1 == lseek(Ctx->tempfd, 0, SEEK_SET)) {
	Ctx->status = stError;
    } else while (1) {
	if (-1 == (len = read(Ctx->tempfd, buf, BUFSIZ))) {
	    statusString = "read from tempfile failed: ";
	    statusString += strerror(errno);
	    Ctx->status = stError;
	} else if (-1 == avWriteChunk(buf, len)) {
	    statusString = "write to AV-daemon failed: ";
	    statusString += strerror(errno);
	    Ctx->status = stError;
	} else if (!len) {
	    /* */
	} else {
	    continue;
	}
	break;
    }
}

void Adapter::Xaction::avCheckVersion(void)
{
    FUNCENTER();

    if (-1 == (Ctx->sockfd = doconnect(service->avdsocket))) {
        statusString = "can't initialize AV-daemon socket: ";
        statusString += strerror(errno);
        Ctx->status = stError;
	return;
    } else if (-1 == avWriteCommand("zVERSION")) {
        Ctx->status = stError;
    } else if (-1 == avReadResponse()) {
	Ctx->status = stError;
    } else {
	int major, minor; char s[256];

	if (0 == strncasecmp(Ctx->avbuf, "clamav", 6)) {
	    engine = engineClamav;
	    // commtouch csamd doesn't return a name
	} else if (6 == sscanf(Ctx->avbuf, "[%d.%d|%[.0-9]|%[.0-9]|%[0-9]|%[0-9]]", &major, &minor, s, s, s, s)) {
	    engine = (major > 1 || minor >= 13) ? engineClamav : engineCommtouch;
	} else {
	    Ctx->status = stError;
	}

    }
    close(Ctx->sockfd);
}

// constructor
Adapter::Xaction::Xaction(libecap::shared_ptr < Service > aService, libecap::host::Xaction * x):service(aService), hostx(x),
    receivingVb(opUndecided),
    sendingAb(opUndecided)
{
    engine = engineAuto;
    received = processed = 0;
    trickled = senderror = bypass = false;
    statusString = "OK";
}

Adapter::Xaction::~Xaction()
{
    FUNCENTER();

    cleanup();
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
        Ctx->tempfd = Ctx->sockfd = -1;
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
    cleanup();
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

libecap::Area Adapter::Xaction::abContent(UNUSED size_type offset, UNUSED size_type size)
{
    size_type sz;
    FUNCENTER();

    // required to not raise an exception on the final call with opComplete
    Must(sendingAb == opOn || sendingAb == opComplete);

    // Error?
    if (Ctx->status != stOK) {
        stopVb();
        sendingAb = opComplete;
        // Nothing written so far. We can send an error message!
        if (senderror)
            return ErrorPage();
    }

    // finished receiving?
    if (receivingVb == opComplete || bypass) {
        sz = sizeof(Ctx->buf); // use the whole buffer
        trickled = false;

        // finished sending?
        if (processed >= received && receivingVb == opComplete) {
            sendingAb = opComplete;
            hostx->noteAbContentDone(true);
        }
    } else {
        sz = service->tricklesize;
    }

    // if complete, there is nothing more to return.
    if (sendingAb == opComplete || trickled) {
        trickled = false;
        return libecap::Area::FromTempString("");
    }

    lseek(Ctx->tempfd, processed, SEEK_SET);

    if ((size_type)-1 == (sz = (size_type)read(Ctx->tempfd, Ctx->buf,  sz))) {
        statusString = "can't read from temp file: ";
	statusString += strerror(errno);
	Ctx->status = stError;
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

        libecap::FirstLine *firstLine = &(adapted->firstLine());
        libecap::StatusLine *statusLine = dynamic_cast<libecap::StatusLine*>(firstLine);

        // do not remove the Content-Length header in 'reqmod'
        if (statusLine)
            adapted->header().removeAny(libecap::headerContentLength);

        if (Ctx->status != stOK) {
            // last chance to indicate an error

            const libecap::Name name("Content-Type");
            const libecap::Name disp("Content-Disposition");
            const libecap::Name cenc("Content-Encoding");
            const libecap::Name tran("Content-Transfer-Encoding");
            const libecap::Header::Value value = libecap::Area::FromTempString("text/html");

            adapted->header().removeAny(disp);
            adapted->header().removeAny(name);
            adapted->header().removeAny(cenc);
            adapted->header().removeAny(tran);

            adapted->header().add(name, value);

            if (statusLine)
                statusLine->statusCode(Ctx->status == stError ? 500 : 403);

            senderror = true;
        }

        const libecap::Name name("X-Ecap");
        const libecap::Header::Value value = libecap::Area::FromTempString(ADAPTERNAME);
        adapted->header().add(name, value);

        hostx->useAdapted(adapted);
    }
    hostx->noteAbContentAvailable();
}

// finished reading the virgin body
// if 'bypass' is set everything is fine, otherwise start scanning
void Adapter::Xaction::noteVbContentDone(UNUSED bool atEnd)
{
    FUNCENTER();
    Must(Ctx);
    Must(receivingVb == opOn);

    hostx->vbStopMaking(); // we will not call vbContent() any more

    if (0 == received) {
	/* nothing received => nothing todo */
	hostx->useVirgin();
	receivingVb = opNever;
	return;
    } else if (bypass) {
	receivingVb = opComplete;
    } else {
	receivingVb = opScanning;
	avStart();
	if (Ctx->status == stOK) {
	    while (-2 == avScanResult())
		noteContentAvailable();
	}
	receivingVb = opComplete;
    }
    noteContentAvailable();
}

// 'bypass' will be set to 1 in noteVbContentAvailable() if received >= maxscansize
// 'startTime' is set in Adapter::Xaction::start
// 'lastContent' will be updated everytime Adapter::Xaction::abContent gets called
void Adapter::Xaction::processContent()
{
    time_t now = time(NULL);

    FUNCENTER();

    if (bypass) {
        noteContentAvailable();
    } else if (now < (startTime + service->trickletime)) {
        // maybe there is a chance to report an error to the client
    } else if (now < (lastContent + service->trickletime)) {
        // wait trickletime
    } else {
	// time to send some bits
        noteContentAvailable();
    }
}

void Adapter::Xaction::noteVbContentAvailable()
{
    FUNCENTER();
    Must(receivingVb == opOn);
    Must(Ctx);

    if (Ctx->status == stError) {
        // Tell client not to expect to get more data
	sendingAb = opComplete;
	hostx->noteAbContentDone(true);
	return;
    }

    // get all virgin body
    const libecap::Area vb = hostx->vbContent(0, libecap::nsize);

    if (sendingAb == opUndecided) {

        // Try to read the ContentLength so we can decide whether scanning has
        // to be performed or not.
        if (service->maxscansize && hostx->virgin().header().hasAny(libecap::headerContentLength)) {
            const libecap::Header::Value value =
                hostx->virgin().header().value(libecap::headerContentLength);
            if (value.size > 0) {
                contentlength = strtoul(value.start, NULL, 10);
                if (contentlength > service->maxscansize) {
                    bypass = 1;
		    Logger(libecap::flXaction) << "Content-Length " << contentlength << " exceeds max scansize: skipping";
		}
            }
        }

	checkFileType(vb);

        if (Ctx->status != stOK) {
            sendingAb = opWaiting;
	    noteContentAvailable();
	    return;
	} else if (mustscan) {
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

    Must(Ctx->tempfd != -1);
    lseek(Ctx->tempfd, 0, SEEK_END);

    // write body to temp file
    if ((int)vb.size != write(Ctx->tempfd, vb.start, vb.size)) {
        statusString = "can't write to temp file: ";
        statusString += strerror(errno);
        Ctx->status = stError;
        return;
    }

    received += vb.size;

    // we have a copy; do not need vb any more
    hostx->vbContentShift(vb.size);

    // set bypass flag it we received more than maxscansize bytes
    if (service->maxscansize && received >= service->maxscansize)
        bypass = 1;

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
