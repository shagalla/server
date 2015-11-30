#include <gssapi/gssapi.h>
#include <string.h>
#include <stdio.h>
#include <mysql/plugin_auth.h>
#include <mysqld_error.h>
#include <mysql.h>

extern void log_client_error(MYSQL *mysql,const char *fmt,...);

static void debug_status(OM_uint32 status_code)
{
OM_uint32 message_context;

OM_uint32 maj_status;
OM_uint32 min_status;
gss_buffer_desc status_string;

message_context = 0;

do {

     maj_status = gss_display_status(
               &min_status,
               status_code,
               GSS_C_GSS_CODE,
               GSS_C_NO_OID,
               &message_context,
               &status_string);

     fprintf(stderr, "%.*s\n", \
               (int)status_string.length, \
               (char *)status_string.value);

     gss_release_buffer(&min_status, &status_string);

} while (message_context != 0);
}

/* This sends the error to the client */
static void log_error(MYSQL *mysql, OM_uint32 major, OM_uint32 minor, const char *msg)
{
  if (GSS_ERROR(major))
  {
    log_client_error(mysql,"Client GSSAPI error (major %u, minor %u) : %s", 
		     major, minor, msg);
  }
  else
  {
    log_client_error(mysql, "Client GSSAPI error : %s", msg);
  }
}

int auth_client(char *target_name, char *mech, MYSQL *mysql, MYSQL_PLUGIN_VIO *vio)
{
  int len=0;
  int ret= CR_ERROR;
  OM_uint32 major= 0, minor= 0;
  
  gss_ctx_id_t ctxt= GSS_C_NO_CONTEXT;
  gss_cred_id_t cred= GSS_C_NO_CREDENTIAL;
  gss_buffer_desc target_name_buf, input;
  gss_name_t service_name;

  /* import principal from plain text */
  target_name_buf.length= strlen(target_name);
  target_name_buf.value= (void *) target_name;
  major= gss_import_name(&minor, &target_name_buf, GSS_C_NT_USER_NAME, &service_name);

  if (GSS_ERROR(major))
  {
    log_error(mysql, major, minor, "gss_import_name");
    return CR_ERROR;
  }
  
  input.length= 0;
  input.value= NULL;

  do
  {
    gss_buffer_desc output= {0, NULL};
    major= gss_init_sec_context(&minor, cred, &ctxt, service_name,
                                GSS_C_NO_OID, 0, 0, GSS_C_NO_CHANNEL_BINDINGS,
                                &input, NULL, &output, NULL, NULL);
    printf("init sec context returns %d/%d output len %d\n",major,minor,(int)output.length);
    debug_status(major);
    printf("minor:\n");
    debug_status(minor);
    printf("continue needed %d\n",GSS_S_CONTINUE_NEEDED);
    if (output.length)
    {
      /* send credential */
      if(vio->write_packet(vio, output.value, output.length))
      {
        /* Server error packet contains detailed message. */
        ret= CR_OK_HANDSHAKE_COMPLETE; 
        gss_release_buffer (&minor, &output);
	printf("write packet failed");
        goto cleanup;
      }
    }
    gss_release_buffer (&minor, &output);
    
    if (GSS_ERROR(major))
    {
       log_error(mysql, major, minor,"gss_init_sec_context");
       goto cleanup;
    }
    
    if (major & GSS_S_CONTINUE_NEEDED)
    {
      len= vio->read_packet(vio, (unsigned char **) &input.value);
      if (len <= 0)
      {
        /* Server error packet contains detailed message. */
        printf("read packet failed\n");
        ret= CR_OK_HANDSHAKE_COMPLETE; 
        goto cleanup;
      }
      input.length= len;
    }
  } while (major & GSS_S_CONTINUE_NEEDED);

  if(major != GSS_S_COMPLETE)
    printf("major = %d\n", major);
  ret= CR_OK;
  printf("OK");
cleanup:

  gss_release_name(&minor, &service_name);
  if (ctxt != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);
  if (cred != GSS_C_NO_CREDENTIAL)
    gss_release_cred(&minor, &cred);

  return ret;
}
