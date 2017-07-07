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

#ifndef _ADAPTER_AVSCAN_XACTION_H
#define _ADAPTER_AVSCAN_XACTION_H 1

#include <stdint.h>

namespace Adapter
{                               // not required, but adds clarity

using libecap::size_type;
using libecap::StatusLine;

/**
 * Class to wrap the buffering part of the ecap transaction.
 *
 * Writes incoming data into a file or a buffer, depending on
 * the createFile Parameter of the makeBuffer method and whether
 * or not discardFile() is called at some point.
 *
 * storeContent and shiftContent move a virtual index pointer,
 * getContent can be used to retrieve data from that index pointer.
 */
class AbBuffer {
public:
    ~AbBuffer();

    /** Signal that no file containing the complete data is
     *  needed any longer. */
    void discardFile();

    /** Get next len bytes from buffer .
     * @param[in] len number of bytes to retrieve
     * @return Area containing at most len bytes (may be less)
     */
    libecap::Area getContent(size_type len);

    /** Signal that next len bytes have been processed and are
     * no longer needed.
     *
     * Moves the read pointer by len. len must not be larger than
     * the number of bytes available in the buffer.
     *
     * @param[in] len number of bytes that can be discarded
     */
    void shiftContent(size_type len);

    /** Store next len bytes to some buffer. Moves the write
     * index forward by the number of bytes returned
     *
     * @param data Area to store
     * @param force if set to true, copy data into additional buffer that
     *        is allocated on the fly --> workaround for missing
     *        notifications from ecap-Host
     * @return number of bytes actually stored (may be less than data.size)
     */
    size_type storeContent(const libecap::Area& data, bool force);

    /** Total number of bytes buffered.
     */
    uint64_t numReceived();

    /** Total number of bytes returned.
     */
    uint64_t numReturned();

    /** Checks if there is currently data in the buffer.
     * @return true buffer is empty
     *         false buffer has some data available */
    bool isEmpty();

    /** Return file descriptor that can be used to access the written
     * buffer data. Only valid if buffer is NOT in bypass mode
     *
     * @return readonly file descriptor to written data
     */
    int getReadonlyFd();

    static std::tr1::shared_ptr<AbBuffer> makeBuffer(bool createFile, libecap::shared_ptr<const Service> service, std::string& statusString);

private:
    static const size_type BUFSIZE = 8192;
    static const size_type MASK = BUFSIZE - 1;

    libecap::Area getContentFromFile(size_type len);
    libecap::Area getContentFromBuffer(size_type len);
    size_type numReadable();

    AbBuffer(bool bypass,
             libecap::shared_ptr<const Service> service,
             std::string& statusString);

    std::string& statusString;
    bool bypass;
    size_type fileOffset; //< offset of read pos relative to current pos
    int writefd; //< internally used read/write file descriptor
    int rofd; //< file descriptor to data that may be used externally
    int rofd_internal; //< readonly file descriptor for internal use
    char buf[BUFSIZE];
    size_type readpos;
    size_type writepos;
    uint64_t received;
    uint64_t returned;
    libecap::Area lastChunkHack;
};

/*
 * Implementation of the Adapter interface of libecap::Xaction.
 */
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

    typedef enum { opUndecided, opWaiting, opOn, opScanning, opComplete, opNever } OperationState;
    typedef enum { stOK, stError, stInfected, stBlocked } ScanState;

    OperationState receivingVb;
    OperationState sendingAb;

    struct Ctx
    {
        int sockfd;
        int status;
        char avbuf[BUFSIZ];
    } *Ctx;

    std::string statusString;

    libecap::Area ErrorPage(void);
    void avStart(void);
    void avStartClamav(void);
    void avStartCommtouch(void);
    void avWriteStream(void);
    void avCheckVersion(void);
    int  avScanResult(void);
    int  avScanResultClamav(void);
    int  avScanResultCommtouch(void);
    int  avReadResponse(void);
    int  avWriteCommand(const char *command);
    int  avWriteChunk(char *buf, ssize_t len);
    void processContent(void);
    void checkFileType(libecap::Area area);
    void noteContentAvailable(void);
    void cleanup(void);
    bool abCheckFinished();
    void vbFinished();
    void vbGetChunk();

    ScanEngine engine;
    time_t startTime;
    time_t lastContent;
    bool mustscan;
    bool trickled;
    bool senderror;
    bool bypass;
    bool hostDone;
    libecap::shared_ptr<AbBuffer> tmpbuf;
};
} // namespace Adapter

#endif // _ADAPTER_AVSCAN_XACTION_H
