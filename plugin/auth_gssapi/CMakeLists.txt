IF (WIN32)
 SET(USE_SSPI 1)
ENDIF()

IF(USE_SSPI)
    SET(GSSAPI_LIB secur32)
    SET(GSSAPI_CLIENT sspi_client.c)
	SET(GSSAPI_SERVER sspi_server.c)
	SET(GSSAPI_ERRMSG sspi_errmsg.c)
ELSE()
 CHECK_INCLUDE_FILES("gssapi/gssapi.h;gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" HAVE_GSSAPI_H)
 FIND_LIBRARY(GSSAPI_LIB gssapi_krb5)
 IF(HAVE_GSSAPI_H AND GSSAPI_LIB)
 	SET(GSSAPI_CLIENT gssapi_client.c)
	SET(GSSAPI_SERVER gssapi_server.c)
	SET(GSSAPI_ERRMSG gssapi_errmsg.c)
 ELSE()
    # Can't build plugin 
    RETURN()
 ENDIF()
ENDIF ()


MYSQL_ADD_PLUGIN(auth_gssapi server_plugin.c ${GSSAPI_SERVER} ${GSSAPI_ERRMSG}
                 LINK_LIBRARIES ${GSSAPI_LIB}
                 MODULE_ONLY)

MYSQL_ADD_PLUGIN(auth_gssapi_client client_plugin.c ${GSSAPI_CLIENT} ${GSSAPI_ERRMSG}
                 LINK_LIBRARIES ${GSSAPI_LIB}
                 MODULE_ONLY)
