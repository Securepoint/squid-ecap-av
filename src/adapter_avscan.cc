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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <inttypes.h>    // uint32_t
#include <arpa/inet.h>    // htonl

#include <fstream>
#include <sstream>
#include <map>
#include <list>
#include <iostream>
#include <string>
#include <cerrno>

#include <libecap/common/message.h>
#include <libecap/common/errors.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/named_values.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>
#include <libecap/host/host.h>

#include "adapter_avscan_Service.h"
#include "adapter_avscan_Xaction.h"
#include "adapter_avscan_Logger.h"
#include "adapter_avscan.h"

using namespace std;

int Adapter::AbBuffer::getReadonlyFd() {
    Must(!bypass);
    Must(rofd_internal != -1);
    if (bypass || rofd_internal == -1) {
        return -1;
    } else {
        return rofd;
    }
}

void Adapter::AbBuffer::discardFile()
{
    bypass = true;
}

libecap::Area Adapter::AbBuffer::getContentFromFile(size_type len)
{
    char buf[len];
    size_type nRead;

    LOG_DBG("Getting from file fileOffset=%u", fileOffset);
    Must(rofd_internal != -1);

    if (-1 == lseek(rofd_internal, -((off_t)fileOffset), SEEK_CUR)) {
        statusString = "can't seek temp file: ";
        statusString += strerror(errno);
        LOG_DBG("Error seek");
        return libecap::Area::FromTempString("");
    } else if ((size_type)-1 == (nRead = (size_type)read(rofd_internal, buf, len))) {
        statusString = "can't read from temp file: ";
        statusString += strerror(errno);
        LOG_DBG("Error read");
        return libecap::Area::FromTempString("");
    }

    fileOffset = nRead;

    if (bypass && fileOffset == 0) {
        // means we read all content from file and need it no longer;
        // close it and use memory buffer from now on
        LOG_DBG("closing tempfd, bypass continuing with memory buffer");
        close(rofd_internal);
        rofd_internal = -1;
        close(writefd);
        writefd = -1;
        return libecap::Area::FromTempString("");
    }

    LOG_DBG("Read returned successful: %u", nRead);
    return libecap::Area::FromTempBuffer(buf, nRead);
}

Adapter::size_type Adapter::AbBuffer::numReadable()
{
    return writepos > readpos ? writepos - readpos : BUFSIZE - readpos;
}

libecap::Area Adapter::AbBuffer::getContentFromBuffer(size_type len)
{
    // only read from mem buffer in bypass mode and if all
    // data has been flushed from the temporary file

    size_type size;
    if (writepos == readpos) {
        LOG_DBG("getContent: writepos=%u readpos=%u return=%u", writepos, readpos, 0);
        return libecap::Area::FromTempString("");
    } else {
        size = numReadable();
        size = size >= len ? len : size;
        LOG_DBG("getContent: writepos=%u readpos=%u size=%u", writepos, readpos, size);

        return libecap::Area::FromTempBuffer(&(buf[readpos]), size);
    }
}

libecap::Area Adapter::AbBuffer::getContent(size_type len)
{
    if (bypass && rofd_internal == -1) {
        return getContentFromBuffer(len);
    } else {
        return getContentFromFile(len);
    }
}

void Adapter::AbBuffer::shiftContent(size_type len)
{
    LOG_DBG("shiftContent: len=%u", len);
    returned += len;
    if (bypass && rofd_internal == -1) {
        readpos = (readpos + len) & MASK;
        LOG_DBG("%s: Shift buffer by %u; new pos=%u", __FUNCTION__, len, readpos);
    } else {
        Must(fileOffset >= len);
        UNUSED size_type old = fileOffset;
        fileOffset -= len;
        LOG_DBG("Shift file by %u; fileOffset_old=%u fileOffset_new=%u", len, old, fileOffset);
    }
}

bool Adapter::AbBuffer::isEmpty()
{
    return returned >= received;
}

Adapter::size_type Adapter::AbBuffer::storeContent(const libecap::Area& data)
{
    size_type nWritten = 0;
    if (bypass && rofd_internal == -1) {
        size_type size;
        LOG_DBG("storeContent: storing to buffer: readpos=%u writepos=%u data.size=%u", readpos, writepos, data.size);

        // improvable, may lead to writes of a single byte
        // readpos must not equal writepos because this signifies an empty buffer
        // if readpos == 0, writepos at max may be BUFSIZE - 1
        // alternative would be to loop content into a temporary buffer and return that
        size = writepos < readpos
                ? readpos - 1 - writepos
                : readpos == 0
                    ? BUFSIZE - 1 - writepos
                    : BUFSIZE - writepos;
        LOG_DBG("storing to buffer: size=%u", size);
        size = size >= data.size ? data.size : size;
        LOG_DBG("storing to buffer: size=%u", size);
        std::copy(data.start, data.start + size, &(buf[writepos]));
        writepos = (writepos + size) & MASK;
        nWritten = size;
        LOG_DBG("%s: writepos=%u nWritten=%u", __FUNCTION__, writepos, nWritten);
    } else {
        if (writefd < 0) {
            Must(false);
            return 0;
        } else {
            lseek(writefd, 0, SEEK_END);
            while (nWritten < data.size) {
                const char *pos = data.start+nWritten;
                size_type toWrite = data.size-nWritten;
                ssize_t n = write(writefd, pos, toWrite);
                if (n < 0) {
                    LOG_DBG("Error writing to file: nWritten=%d vb.size=%u pos=%p toWrite=%u", nWritten, data.size, pos, toWrite);
                    statusString = "can't write to temp file: ";
                    statusString += strerror(errno);
                    return -1;
                }
                nWritten += n;
                LOG_DBG("storeContent: written to tmpfile: nWritten=%d vb.size=%u pos=%p toWrite=%d", nWritten, data.size, pos, toWrite);
            }
        }
    }
    received += nWritten;
    LOG_DBG("storeContent: received=%llu", received);
    return nWritten;
}

uint64_t Adapter::AbBuffer::numReturned()
{
    return returned;
}

uint64_t Adapter::AbBuffer::numReceived()
{
    return received;
}

Adapter::AbBuffer::AbBuffer(bool createFile,
                            libecap::shared_ptr<const Service> service,
                            std::string& statusString) :
        statusString(statusString),
        bypass(createFile),
        fileOffset(0),
        writefd(-1),
        rofd(-1),
        rofd_internal(-1),
        readpos(0),
        writepos(0),
        received(0),
        returned(0)
{
    FUNCENTER();
    char fn[PATH_MAX];
    mode_t oldmask;

    LOG_DBG("opening tmp file at %s/squid-ecap-XXXXXX", service->tempdir.c_str());
    snprintf(fn, PATH_MAX - 1, "%s/squid-ecap-XXXXXX", service->tempdir.c_str());
    oldmask = umask(0077);
    writefd = mkstemp((char *)fn);
    umask(oldmask);
    LOG_DBG("opening tmp file at %s", fn);
    rofd = open(fn, O_RDONLY);
    rofd_internal = open(fn, O_RDONLY);
    if (writefd < 0 || rofd < 0 || rofd_internal < 0) {
        statusString = "can't open temp file: ";
        statusString += strerror(errno);
    }
    Must(writefd > 0 && rofd > 0 && rofd_internal > 0);
    unlink(fn);
}

Adapter::AbBuffer::~AbBuffer()
{
    if (writefd) {
        close(writefd);
    }
    if (rofd) {
        close(rofd);
    }
    if (rofd_internal) {
        close(rofd_internal);
    }
}

libecap::shared_ptr<Adapter::AbBuffer>
Adapter::AbBuffer::makeBuffer(bool createFile,
        libecap::shared_ptr<const Service> service,
        std::string& statusString)
{
    return libecap::shared_ptr<Adapter::AbBuffer>(new AbBuffer(createFile, service, statusString));
}

class AppendingVisitor : public libecap::NamedValueVisitor {
public:
    AppendingVisitor(const std::map<std::string, std::string> &keyMapping,
                     std::map<std::string, std::string> &appendTo) :
        keymap(keyMapping),
        appendTo(appendTo)
    {};

    virtual ~AppendingVisitor() {};

    virtual void visit(const libecap::Name &name, const libecap::Area &value)
    {
        if (keymap.count(name.image()) > 0) {
            std::string tmp = keymap.at(name.image());
            appendTo[tmp] = value.toString();
        } else {
            appendTo[name.image()] = value.toString();
        }
    }

private:
    const std::map<std::string, std::string> &keymap;
    std::map<std::string, std::string> &appendTo;
};

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

void Adapter::Xaction::log_result() {
    std::stringstream message;
    std::map<std::string, std::string> resultDict;

    // also emit old format, just in case somebody is relying on it
    std::stringstream old;

    if (Ctx) {
        if (Ctx->status == stInfected) {
            resultDict[LOG_KEY_STATUS] = "INFECTED";
            old << "INFECTED, " << statusString;
        } else if (Ctx->status == stBlocked) {
            resultDict[LOG_KEY_STATUS] = "BLOCKED";
            old << "BLOCKED, " << statusString;
        } else if (statusString != "OK") {
            resultDict[LOG_KEY_STATUS] = "ERROR";
            message << "\"ERROR\" reason=\"" << statusString << "\"";
            old << statusString;
        } else {
            // do not log anything
            return;
        }
        resultDict[LOG_KEY_REASON] = statusString;
        resultDict[LOG_KEY_FILESIZE] = std::to_string(tmpbuf ? tmpbuf->numReceived() : 0);

        // add URL from original request
        const libecap::Message &originalMessage = hostx->cause();
        try {
            const libecap::RequestLine &originalReq = dynamic_cast<const libecap::RequestLine&>(originalMessage.firstLine());
            resultDict[LOG_KEY_URL] = originalReq.uri().toString();
        } catch (const std::bad_cast &e) {
            // we should always have some request
        }

        // keep "old" output format around to avoid surprises
        Logger(ilCritical|flXaction) << old.str();

        std::list<std::string> keys = { LOG_KEY_STATUS, LOG_KEY_REASON, LOG_KEY_URL, LOG_KEY_FILESIZE };

        if (service->options) {
            try {
                AppendingVisitor visi(service->options->getTranslateKeys(), resultDict);
                hostx->visitEachOption(visi);
            } catch (const std::exception &e) {
                Logger(ilCritical|flXaction) << e.what();
            }

            const std::list<std::string> &additionalKeys = service->options->getAdditionalKeys();
            for (auto it = additionalKeys.begin(); it != additionalKeys.end(); ++it) {
                keys.push_back(*it);
            }
        }

        for (auto it = keys.begin(); it != keys.end(); ++it) {
            message << *it << "=\"" << resultDict[*it] << "\" ";
        }
        Logger(ilCritical|flXaction) << message.str();
    }
}

void Adapter::Xaction::cleanup(void) {
    if (Ctx) {
        if (-1 != Ctx->sockfd)
            close(Ctx->sockfd);

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

int iowait(int fd, int timeout, short what)
{
    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = what;
    pfd.revents = 0;
    return poll(&pfd, 1, timeout * 1000);
}

int Adapter::Xaction::avWriteCommand(const char *command)
{
    int n, r;

    FUNCENTER();

    Must(command);
    n = strlen(command) + 1;

    if (n == (r = write(Ctx->sockfd, command, n))) {
        return n;
    } else if (r == -1 && errno != EAGAIN) {
        statusString = "can't write to AV-daemon socket: ";
        statusString += strerror(errno);
    } else if (-1 == (r = iowait(Ctx->sockfd, service->writetimeout, POLLOUT))) {
        statusString = "AV-daemon (w)socket iowait failed: ";
        statusString += strerror(errno);
    } else if (0 == r) {
        statusString = "AV-daemon (w)socket timeout";
    } else {
        // write the trailing NULL character too
        return write(Ctx->sockfd, command, n);
    }
    return -1;
}

int Adapter::Xaction::avReadResponse(void)
{
    int n, off = 0;

    FUNCENTER();

    while (1) {
        if (-1 == (n = iowait(Ctx->sockfd, service->readtimeout, POLLIN))) {
            statusString = "AV-daemon (r)socket iowait failed: ";
            statusString += strerror(errno);
        } else if (0 == n) {
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

    Must(tmpbuf != NULL);
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
    *(int *)CMSG_DATA(cmsg) = tmpbuf->getReadonlyFd();
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
    //    ' OK'

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
    int flags, sockfd = -1;

    if (-1 != (sockfd = socket(AF_LOCAL, SOCK_STREAM, 0))) {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_LOCAL;
        strncpy(address.sun_path, aPath.c_str(), sizeof(address.sun_path) - 1);
        if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) == -1) {
            close(sockfd);
            sockfd = -1;
        }
        if (-1 != (flags = fcntl(sockfd, F_GETFL))) {
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        }
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
    FUNCENTER();
    char buf[BUFSIZ];
    ssize_t len;
    Must(tmpbuf != NULL);

    int fd = tmpbuf->getReadonlyFd();
    // Set offset to the beginning of the file
    if (fd > 0) {
        if (-1 == lseek(fd, 0, SEEK_SET)) {
            Ctx->status = stError;
        } else while (1) {
            if (-1 == (len = read(fd, buf, BUFSIZ))) {
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
    } else {
        Ctx->status = stError;
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
Adapter::Xaction::Xaction(libecap::shared_ptr < Service > aService, libecap::host::Xaction * x) :
        service(aService),
        hostx(x),
        receivingVb(opUndecided),
        sendingAb(opUndecided),
        hostDone(false)
{
    engine = engineAuto;
    trickled = senderror = bypass = mustscan = false;
    statusString = "OK";
    Ctx = 0;
    startTime = lastContent = 0;
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
        Ctx->sockfd = -1;
        startTime = time(NULL);
    } else {
        hostx->useVirgin();
        receivingVb = opNever;
    }
}

void Adapter::Xaction::stop()
{
    FUNCENTER();
    log_result();
    cleanup();
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
    Must(hostx->virgin().body());    // that is our only source of ab content

    // we are or were receiving or are finished but still scanning
    Must(receivingVb == opOn || receivingVb == opComplete || receivingVb == opScanning);

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
        if (senderror) {
            return ErrorPage();
        } else {
            // reaching this point, we already started trickling and can only
            // abort the process in case of an error (e.g., virus detected)
            hostx->adaptationAborted();
            return libecap::Area::FromTempString("");
        }
    }

    // finished receiving?
    if (receivingVb == opComplete || bypass) {
        sz = BUFSIZ;
        trickled = false;
    } else {
        sz = service->tricklesize;
    }

    // if complete, there is nothing more to return.
    if (sendingAb == opComplete || trickled) {
        trickled = false;
        LOG_DBG("%s: return empty buffer", __FUNCTION__);
        return libecap::Area::FromTempString("");
    }

    Must(tmpbuf != NULL);
    LOG_DBG("abContent: try to get %u bytes; processed=%llu", sz, tmpbuf->numReturned());
    trickled = true;
    lastContent = time(NULL);

    return tmpbuf->getContent(sz);;
}

void Adapter::Xaction::abContentShift(size_type size)
{
    FUNCENTER();
    LOG_DBG("abContentShift: %u", size);
    Must(sendingAb == opOn);
    Must(tmpbuf != NULL);
    tmpbuf->shiftContent(size);

    // check if we are finished with abContent
    abCheckFinished();

    if (tmpbuf->isEmpty()) {
        LOG_DBG("%s: buffer ready to read more --> get more", __FUNCTION__);
        // retrieve more data if our buffer is ready to handle it
        vbGetChunk();
    }
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

        LOG_DBG("%s: calling useAdapted()", __FUNCTION__);
        hostx->useAdapted(adapted);
    }
    LOG_DBG("%s: calling noteAbContentAvailable()", __FUNCTION__);
    hostx->noteAbContentAvailable();
}

bool Adapter::Xaction::abCheckFinished()
{
    FUNCENTER();
    if (tmpbuf->isEmpty() && receivingVb == opComplete) {
        LOG_DBG("%s: last of ab content processed, send notification", __FUNCTION__);
        sendingAb = opComplete;
        hostx->noteAbContentDone(true);
        return true;
    } else {
        return false;
    }
}

void Adapter::Xaction::vbFinished()
{
    Must(Ctx);
    Must(receivingVb == opOn);
    Must(tmpbuf != NULL);

    hostx->vbStopMaking(); // we will not call vbContent() any more

    if (0 == tmpbuf->numReceived()) {
        /* nothing received => nothing to be done */
        hostx->useVirgin();
        receivingVb = opNever;
        return;
    } else if (bypass) {
        receivingVb = opComplete;
    } else {
        receivingVb = opScanning;
        avStart();
        if (Ctx->status == stOK) {

            // keep trickling data while AV scanner is busy (-2 signifies
            // timeout condition
            while (-2 == avScanResult())
                noteContentAvailable();
        }
        receivingVb = opComplete;
    }

    // arriving here
    if (!abCheckFinished()) {
        noteContentAvailable();
    }
}

// finished reading the virgin body
// if 'bypass' is set everything is fine, otherwise start scanning
void Adapter::Xaction::noteVbContentDone(UNUSED bool atEnd)
{
    FUNCENTER();

    // there may still be some data available that we have not
    // yet retrieved completely, so just flag that the host
    // is done
    hostDone = true;
    vbGetChunk();
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

void Adapter::Xaction::vbGetChunk()
{
    size_type numStored;
    Must(receivingVb == opOn);
    Must(Ctx);

    if (Ctx->status == stError) {
        // Tell client not to expect to get more data
        sendingAb = opComplete;
        Logger(ilCritical) << "finished err";
        hostx->noteAbContentDone(true);
        return;
    }

    // get next chunk of virgin body
    const libecap::Area lastVb = hostx->vbContent(0, libecap::nsize);

    LOG_DBG("vbContent: start=%p size=%u", lastVb.start, lastVb.size);
    if (sendingAb == opUndecided) {
        uint64_t contentlength;
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

        checkFileType(lastVb);

        if (Ctx->status != stOK) {
            LOG_DBG("error case");
            sendingAb = opWaiting;
            noteContentAvailable();
            return;
        } else if (mustscan) {
            LOG_DBG("mustscan=true");
            try {
                tmpbuf = AbBuffer::makeBuffer(bypass, service, statusString);
                // go to state waiting, hostx->useAdapted() will be called later
                // via noteContentAvailable()
                sendingAb = opWaiting;
            } catch (libecap::TextException& e) {
                Ctx->status = stError;
                throw e;
            }
        } else {
            LOG_DBG("use virgin");
            // nothing to do, just send the vb
            hostx->useVirgin();
            abDiscard();
            return;
        }
    }

    LOG_DBG("%s: start=%p size=%u bypass=%d mustscan=%d hostDone=%d", __FUNCTION__, lastVb.start, lastVb.size, bypass, mustscan, hostDone);

    Must(tmpbuf != NULL);

    numStored = tmpbuf->storeContent(lastVb);
    hostx->vbContentShift(numStored);
    LOG_DBG("%s: shifted vb by %d", __FUNCTION__, numStored);

    // set bypass flag if we received more than maxscansize bytes
    if (service->maxscansize && tmpbuf->numReceived() >= service->maxscansize) {
        bypass = 1;
        tmpbuf->discardFile();
    }

    LOG_DBG("hostDone=%d; last chunk size=%u last chunk stored=%u", hostDone, lastVb.size, numStored);

    // if host has finished already, check if we read all virgin
    // body, because there won't be another notification if we did and
    // do NOT call processContent again as this is handled by vbFinished
    if (hostDone) {
        LOG_DBG("finished reading virgin body");
        vbFinished();
    } else {
        if (sendingAb == opOn || sendingAb == opWaiting) {
            processContent();
        }
    }
}

void Adapter::Xaction::noteVbContentAvailable()
{
    FUNCENTER();
    vbGetChunk();
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
