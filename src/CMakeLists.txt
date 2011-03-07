ADD_LIBRARY(squid-ecap-clamd SHARED
  adapter_clamd.cc
)

FIND_LIBRARY(LIBECAP ecap)
IF (NOT LIBECAP)
  MESSAGE(FATAL_ERROR "
  The ECAP library is required to build squid-ecap-clamd.
  The latest version is always available at http://www.e-cap.org/"
  )
ENDIF()

SET_TARGET_PROPERTIES(squid-ecap-clamd PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(squid-ecap-clamd ${LIBECAP})
