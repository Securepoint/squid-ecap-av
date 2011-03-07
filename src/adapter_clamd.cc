/*
 *	Securepoint eCAP clamd Adapter
 *	Copyright (C) 2011 Gernot Tenchio, Securepoint GmbH, Germany.
 *
 *	http://www.securepoint.de/
 * 
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *	 
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	 
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *	-----------------------------------------------------------------
 *
 *	This eCAP adapter is based on the eCAP adapter sample,
 *	available under the following license:
 *
 *	Copyright 2008 The Measurement Factory.
 *	All rights reserved.
 *
 *	This Software is licensed under the terms of the eCAP library (libecap),
 *	including warranty disclaimers and liability limitations.
 * 
 *	http://www.e-cap.org/
 * 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <iostream>
#include <libecap/common/message.h>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>

const char *socketpath = "/tmp/clamd.sock";

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
    virtual void configure(const Config & cfg);
    virtual void reconfigure(const Config & cfg);

    // Lifecycle
    virtual void start();       // expect makeXaction() calls
    virtual void stop();        // no more makeXaction() calls until start()
    virtual void retire();      // no more makeXaction() calls

    // Scope (XXX: this may be changed to look at the whole header)
    virtual bool wantsUrl(const char *url) const;

    // Work
    virtual libecap::adapter::Xaction * makeXaction(libecap::host::Xaction *
      hostx);
  };

  class Xaction:public libecap::adapter::Xaction
  {
  public:
    Xaction(libecap::host::Xaction * x);
    virtual ~ Xaction();

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
          libecap::host::Xaction * lastHostCall();      // clears hostx

  private:
          libecap::host::Xaction * hostx;       // Host transaction rep

    typedef enum
    { opUndecided, opOn, opComplete, opNever } OperationState;
    OperationState receivingVb;
    OperationState sendingAb;

    struct clamdContext
    {
      int sockfd;
      char *buf;
      size_type bufsize;
    }           *clamdContext;

    void clamdInitialize();
    void clamdFinalize();

    struct
    {
      bool responseCacheControlOk;
      bool responseContentTypeOk;
      bool requestAcceptEncodingOk;
    } requirements;

    bool requirementsAreMet();
  };

}                               // namespace Adapter

/**
 * Determines if the response can be compressed or not. 
 */
bool Adapter::Xaction::requirementsAreMet()
{

  if (!requirements.responseCacheControlOk) {
    return false;
  }

  if (!requirements.responseContentTypeOk) {
    return false;
  }

  if (!requirements.requestAcceptEncodingOk) {
    return false;
  }

  return true;
}

/**
 * Initializes the clamd data structures.
 */
void Adapter::Xaction::clamdInitialize()
{
  struct sockaddr_un address;
  int sockfd;

  if (!(clamdContext =
      (struct clamdContext *) malloc(sizeof(struct clamdContext)))) {
    /* error */
  } else if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
    return;
  } else {
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_LOCAL;
    strncpy(address.sun_path, socketpath, sizeof(address.sun_path));

    if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) == -1) {
      close(sockfd);
    } else {
      clamdContext->sockfd = sockfd;
    }
  }
}

//
// Close the clamd socket and free the data structures.
//
void Adapter::Xaction::clamdFinalize()
{
  if (clamdContext) {
    close(clamdContext->sockfd);
    free(clamdContext);
    clamdContext = 0;
  }
}

std::string Adapter::Service::uri() const
{
  return "ecap://www.securepoint.de/ecap_clamd";
}

std::string Adapter::Service::tag() const
{
  return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream & os) const
{
  os << "clamd eCAP adapter";
}

void Adapter::Service::configure(const Config &)
{
  // this service is not configurable
}

void Adapter::Service::reconfigure(const Config &)
{
  // this service is not configurable
}

void Adapter::Service::start()
{
  // libecap::adapter::Service::start();
  // custom code would go here, but this service does not have one
  fprintf(stdout,"%s\n", __func__);
}

void Adapter::Service::stop()
{
  // custom code would go here, but this service does not have one
  libecap::adapter::Service::stop();
}

void Adapter::Service::retire()
{
  // custom code would go here, but this service does not have one
  libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(const char *url) const
{
  return true;                  // no-op is applied to all messages
}

libecap::adapter::Xaction *
  Adapter::Service::makeXaction(libecap::host::Xaction * hostx)
{
  return new Adapter::Xaction(hostx);
}

// Constructor
Adapter::Xaction::Xaction(libecap::host::Xaction * x):hostx(x),
receivingVb(opUndecided),
sendingAb(opUndecided)
{
}

// Destructor
Adapter::Xaction::~Xaction()
{
  if (libecap::host::Xaction * x = hostx) {
    hostx = 0;
    x->adaptationAborted();
  }
}

void Adapter::Xaction::start()
{
  clamdContext = 0;

  Must(hostx);
  if (hostx->virgin().body()) {
    receivingVb = opOn;
    hostx->vbMake();            // ask host to supply virgin body
  } else {
    receivingVb = opNever;
  }

  libecap::shared_ptr < libecap::Message > adapted = hostx->virgin().clone();
  Must(adapted != 0);

#if 0
  //
  // Checks if the response Cache-Control header allows transformation of the response.
  //
  static const libecap::Name cacheControlName("Cache-Control");

  // Set default value
  this->requirements.responseCacheControlOk = true;

  if (adapted->header().hasAny(cacheControlName)) {
    const libecap::Header::Value cacheControl =
      adapted->header().value(cacheControlName);

    if (cacheControl.size > 0) {
      std::string cacheControlString = cacheControl.toString(); // expensive

      if (strstr(cacheControlString.c_str(), "no-transform")) {
        this->requirements.responseCacheControlOk = false;
      }
    }
  }
  //
  // Checks the Content-Type response header.
  // At this time, only responses with "text/html" content-type are allowed to be compressed.
  //
  static const libecap::Name contentTypeName("Content-Type");

  // Set default value
  this->requirements.responseContentTypeOk = false;

  if (adapted->header().hasAny(contentTypeName)) {
    const libecap::Header::Value contentType =
      adapted->header().value(contentTypeName);

    if (contentType.size > 0) {
      std::string contentTypeString = contentType.toString();   // expensive

      if (strstr(contentTypeString.c_str(), "text/html")) {
        this->requirements.responseContentTypeOk = true;
      }
    }
  }
#endif

  // delete ContentLength header because we may change the length
  // unknown length may have performance implications for the host
  adapted->header().removeAny(libecap::headerContentLength);

  // Add informational response header    
  static const libecap::Name name("X-Ecap");
  const libecap::Header::Value value =
    libecap::Area::FromTempString("Securepoint eCAP clamd Adapter");
  adapted->header().add(name, value);

  // Add "Vary: Accept-Encoding" response header if Content-Type is "text/html"
  if (requirements.responseContentTypeOk) {
    static const libecap::Name varyName("Vary");
    const libecap::Header::Value varyValue =
      libecap::Area::FromTempString("Accept-Encoding");
    adapted->header().add(varyName, varyValue);

  }

  if (!adapted->body()) {
    sendingAb = opNever;        // there is nothing to send
    lastHostCall()->useAdapted(adapted);
  } else {
    if (requirementsAreMet()) {
      // Remove Content-Location header
      static const libecap::Name contentLocationName("Content-Location");
      adapted->header().removeAny(contentLocationName);

      // Remove ETag response header
      static const libecap::Name eTagName("ETag");
      adapted->header().removeAny(eTagName);

      // Add "Content-Encoding: gzip" response header
      static const libecap::Name contentEncodingName("Content-Encoding");
      const libecap::Header::Value contentEncodingValue =
        libecap::Area::FromTempString("gzip");
      adapted->header().add(contentEncodingName, contentEncodingValue);

      // Add Warning header to response, according to RFC 2616 14.46
      static const libecap::Name warningName("Warning");
      const libecap::Header::Value warningValue =
        libecap::Area::FromTempString("214 Transformation applied");
      adapted->header().add(warningName, warningValue);

      clamdInitialize();
      hostx->useAdapted(adapted);
    } else {
      hostx->useVirgin();
      abDiscard();
    }
  }
}

void Adapter::Xaction::stop()
{
  hostx = 0;
  // the caller will delete
}

void Adapter::Xaction::abDiscard()
{
  Must(sendingAb == opUndecided);       // have not started yet

  sendingAb = opNever;
}

void Adapter::Xaction::abMake()
{
  Must(sendingAb == opUndecided);       // have not yet started or decided not to send
  Must(hostx->virgin().body()); // that is our only source of ab content

  // we are or were receiving vb
  Must(receivingVb == opOn || receivingVb == opComplete);

  sendingAb = opOn;
  hostx->noteAbContentAvailable();
}

void Adapter::Xaction::abMakeMore()
{
  Must(receivingVb == opOn);    // a precondition for receiving more vb
  hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking()
{
  sendingAb = opComplete;
  // we may still continue receiving
}

libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size)
{
  // required to not raise an exception on the final call with opComplete
  Must(sendingAb == opOn || sendingAb == opComplete);

  // if complete, there is nothing more to return.
  if (sendingAb == opComplete) {
    return libecap::Area::FromTempString("");
  }
#if 0
  offset = gzipContext->sendingOffset + offset;
  size = gzipContext->compressedSize - offset;

  return libecap::Area::FromTempBuffer((const char *) &gzipContext->
    gzipBuffer[offset], size);
#endif
  return libecap::Area::FromTempBuffer(clamdContext->buf,
    clamdContext->bufsize);
}

void Adapter::Xaction::abContentShift(size_type size)
{
  Must(sendingAb == opOn);
#if 0
  gzipContext->sendingOffset += size;
  hostx->vbContentShift(gzipContext->lastChunkSize);
#endif
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
  Must(clamdContext);
  Must(receivingVb == opOn);
  
  receivingVb = opComplete;

  if (sendingAb == opOn) {
    hostx->noteAbContentDone(atEnd);
    sendingAb = opComplete;
  }

  clamdFinalize();
}

void Adapter::Xaction::noteVbContentAvailable()
{
  Must(receivingVb == opOn);
  Must(clamdContext);

  // get all virgin body
  const libecap::Area vb = hostx->vbContent(0, libecap::nsize);
#if 0
  // calculate original byte size for GZIP footer
  gzipContext->originalSize += vb.size;

  // store chunk size for contentShift()
  gzipContext->lastChunkSize = vb.size;

  // calculate CRC32 for GZIP footer
  gzipContext->checksum =
    crc32(gzipContext->checksum, (Bytef *) vb.start, vb.size);

  // (re)allocate the gzipBuffer
  gzipContext->gzipBuffer =
    (unsigned char *) realloc(gzipContext->gzipBuffer,
    256 + gzipContext->originalSize);

  // if this is the first content chunk, add the gzip header
  if (gzipContext->originalSize == vb.size) {
    gzipContext->gzipBuffer[0] = (unsigned char) 31;    //      Magic number #1
    gzipContext->gzipBuffer[1] = (unsigned char) 139;   //      Magic number #2
    gzipContext->gzipBuffer[2] = (unsigned char) Z_DEFLATED;    //      Method
    gzipContext->gzipBuffer[3] = (unsigned char) 0;     //      Flags
    gzipContext->gzipBuffer[4] = (unsigned char) 0;     //      Mtime #1
    gzipContext->gzipBuffer[5] = (unsigned char) 0;     //      Mtime #2
    gzipContext->gzipBuffer[6] = (unsigned char) 0;     //      Mtime #3
    gzipContext->gzipBuffer[7] = (unsigned char) 0;     //      Mtime #4
    gzipContext->gzipBuffer[8] = (unsigned char) 0;     //      Extra flags
    gzipContext->gzipBuffer[9] = (unsigned char) 3;     //      Operatin system: UNIX

    gzipContext->compressedSize = 10;
  }

  gzipContext->zstream.next_in = (Bytef *) vb.start;
  gzipContext->zstream.avail_in = vb.size;
  gzipContext->zstream.next_out =
    (Bytef *) & gzipContext->gzipBuffer[gzipContext->compressedSize];
  gzipContext->zstream.avail_out =
    256 + gzipContext->originalSize - gzipContext->compressedSize;
  gzipContext->zstream.total_out = 0;

  int rc = deflate(&gzipContext->zstream, Z_SYNC_FLUSH);

  gzipContext->compressedSize += gzipContext->zstream.total_out;
#endif

  if (sendingAb == opOn) {
    hostx->noteAbContentAvailable();
  }
}

bool Adapter::Xaction::callable() const
{
  return hostx != 0;            // no point to call us if we are done
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction * Adapter::Xaction::lastHostCall()
{
  libecap::host::Xaction * x = hostx;
  Must(x);
  hostx = 0;
  return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered =
  (libecap::RegisterService(new Adapter::Service), true);
