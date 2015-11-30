IF (WIN32)
 SET(USE_SSPI 1)
ENDIF()

IF(USE_SSPI)
  SET(GSSAPI_LIB secur32)
  ADD_DEFINITIONS(-DPLUGIN_SSPI)
  SET(GSSAPI_CLIENT sspi_client.cc)
  SET(GSSAPI_SERVER sspi_server.cc)
  SET(GSSAPI_ERRMSG sspi_errmsg.cc)
ELSE()
 CHECK_INCLUDE_FILES("gssapi/gssapi.h" HAVE_GSSAPI_H)
 FIND_LIBRARY(GSSAPI_LIB gssapi_krb5)
 IF(HAVE_GSSAPI_H AND GSSAPI_LIB)
   ADD_DEFINITIONS(-DPLUGIN_GSSAPI)
   SET(GSSAPI_CLIENT gssapi_client.cc)
   SET(GSSAPI_SERVER gssapi_server.cc)
   SET(GSSAPI_ERRMSG gssapi_errmsg.cc)
 ELSE()
   # Can't build plugin 
   RETURN()
 ENDIF()
ENDIF ()


MYSQL_ADD_PLUGIN(auth_gssapi server_plugin.cc ${GSSAPI_SERVER} ${GSSAPI_ERRMSG}
                 LINK_LIBRARIES ${GSSAPI_LIB}
                 MODULE_ONLY)

MYSQL_ADD_PLUGIN(auth_gssapi_client client_plugin.cc ${GSSAPI_CLIENT} ${GSSAPI_ERRMSG}
                 LINK_LIBRARIES ${GSSAPI_LIB}
                 MODULE_ONLY)
