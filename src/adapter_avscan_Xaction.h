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

#ifndef _ADAPTER_AVSCAN_XACTION_H
#define _ADAPTER_AVSCAN_XACTION_H 1

namespace Adapter
{                               // not required, but adds clarity

using libecap::size_type;
using libecap::StatusLine;

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
    typedef enum { opBuffered, opTrickle, opViralator } OperationMode;
    typedef enum { stOK, stError, stInfected } ScanState;

    OperationState receivingVb;
    OperationState sendingAb;
    OperationMode avMode;

    struct Ctx
    {
        int sockfd;
        int tempfd;
        int status;
        char *tempfn;
        char buf[BUFSIZ];
    } *Ctx;

    std::string statusString;
    void openTempfile(void);

    libecap::Area ErrorPage(void);
    void avStart(void);
    void processContent(void);
    int avReadResponse(void);
    int avWriteCommand(const char *command);
    bool mustScan(libecap::Area area);
    void noteContentAvailable(void);

    size_type received;
    size_type processed;
    size_type contentlength;
    time_t startTime;
    time_t lastContent;
    bool trickled;
    bool senderror;
    bool bypass;
};
} // namespace Adapter

#endif // _ADAPTER_AVSCAN_XACTION_H
