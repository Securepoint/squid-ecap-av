ADD_LIBRARY(ecap_adapter_av SHARED
  adapter_avscan.cc
  adapter_avscan_Service.cc
  adapter_avscan_Logger.cc
)

FIND_PACKAGE(PkgConfig)
PKG_CHECK_MODULES(LIBECAP libecap)
IF(NOT LIBECAP_FOUND)
  FIND_LIBRARY(LIBECAP ecap)
  IF(NOT LIBECAP)
  MESSAGE(FATAL_ERROR "
  The ECAP library is required to build squid-ecap-av.
  The latest version is available at http://www.e-cap.org/."
  )
  ENDIF()
  SET(LIBECAP_LDFLAGS "-lecap")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DV003")
ENDIF()

FIND_LIBRARY(LIBMAGIC magic)
IF(LIBMAGIC)
  SET(LIBMAGIC_LDFLAGS "-lmagic")
ELSE()
  MESSAGE(FATAL_ERROR "
  The libmagic library is required to build squid-ecap-av. Either get it
  from here http://www.darwinsys.com/file/ or install the file development
  package (i.e 'pkcon install file-devel' on fedora)."
  )
ENDIF()

SET_TARGET_PROPERTIES(ecap_adapter_av PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(ecap_adapter_av ${LIBECAP_LDFLAGS} ${LIBMAGIC_LDFLAGS})
INCLUDE_DIRECTORIES(${LIBECAP_INCLUDE_DIRS})

INSTALL(TARGETS ecap_adapter_av DESTINATION ${MODDIR})

