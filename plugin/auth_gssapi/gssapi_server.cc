#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <stdio.h>
#include <mysql/plugin_auth.h>
#include <my_sys.h>
#include <mysqld_error.h>
#include "server_plugin.h"

static gss_name_t service_name = GSS_C_NO_NAME;

/* This sends the error to the client */
static void log_error( OM_uint32 major, OM_uint32 minor, const char *msg)
{
  if (GSS_ERROR(major))
  {
    my_printf_error(ER_UNKNOWN_ERROR,"Server GSSAPI error (major %u, minor %u) : %s", 
      MYF(0), major, minor, msg);
  }
  else
  {
    my_printf_error(ER_UNKNOWN_ERROR, "Server GSSAPI error : %s", MYF(0), msg);
  }
}

int plugin_init()
{
  gss_buffer_desc principal_name_buf;
  OM_uint32 major= 0, minor= 0;
  gss_cred_id_t cred= GSS_C_NO_CREDENTIAL;
  
  /* import service principal from plain text */
  principal_name_buf.length= strlen(srv_principal_name);
  principal_name_buf.value= srv_principal_name;
  major= gss_import_name(&minor, &principal_name_buf, GSS_C_NT_USER_NAME, &service_name);
  if(GSS_ERROR(major))
  {
    log_error(major, minor, "gss_import_name");
    return -1;
  }
  if(srv_keytab_path && *srv_keytab_path)
  {
    setenv("KRB5_KTNAME",srv_keytab_path,1);
  }
  
  /* Check if SPN configuration is OK */
  major= gss_acquire_cred(&minor, service_name, GSS_C_INDEFINITE,
                            GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, NULL,
                            NULL);

  if (GSS_ERROR(major))
  {
    log_error(major, minor, "gss_acquire_cred failed");
    return -1;
  }
  gss_release_cred(&minor, &cred);
  
  return 0;
}

int plugin_deinit()
{
  OM_uint32 minor;
  gss_release_name(&minor, &service_name);
  return 0;
}


int auth_server(MYSQL_PLUGIN_VIO *vio,const char *user, int userlen, int use_full_name)
{

  int rc= CR_ERROR; /* return code */

  /* GSSAPI related fields */
  OM_uint32 major= 0, minor= 0, flags= 0;
  gss_cred_id_t cred= GSS_C_NO_CREDENTIAL; /* credential identifier */
  gss_ctx_id_t ctxt= GSS_C_NO_CONTEXT; /* context identifier */
  gss_name_t client_name;
  gss_buffer_desc client_name_buf, input, output;
  char *client_name_str;

  /* server acquires credential */
  major= gss_acquire_cred(&minor, service_name, GSS_C_INDEFINITE,
                            GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, NULL,
                            NULL);

  if (GSS_ERROR(major))
  {
    log_error(major, minor, "gss_acquire_cred failed");
    goto cleanup;
  }
  
  input.length= 0;
  input.value= NULL;
  do
  {
    /* receive token from peer */
    int len= vio->read_packet(vio, (unsigned char **) &input.value);
    if (len < 0)
    {   
      log_error(0, 0, "fail to read token from client");
      goto cleanup;
    }

    input.length= len;
    major= gss_accept_sec_context(&minor, &ctxt, cred, &input,
                                  GSS_C_NO_CHANNEL_BINDINGS, &client_name,
                                  NULL, &output, &flags, NULL, NULL);
    if (GSS_ERROR(major))
    {
      
      log_error(major, minor, "gss_accept_sec_context");
      rc= CR_ERROR;
      goto cleanup;
    }
    
    /* send token to peer */
    if (output.length)
    {
      if (vio->write_packet(vio, (const uchar *) output.value, output.length))
      {
        gss_release_buffer(&minor, &output);
        log_error(major, minor, "communication error(write)");
        goto cleanup;
      }
      gss_release_buffer(&minor, &output);
    }
  } while (major & GSS_S_CONTINUE_NEEDED);

  /* extract plain text client name */
  major= gss_display_name(&minor, client_name, &client_name_buf, NULL);
  if (major == GSS_S_BAD_NAME)
  {
    log_error(major, minor, "gss_display_name");
    goto cleanup;
  }

  client_name_str= (char *)client_name_buf.value;
  /* 
   * Compare input user name with the actual one. Return success if 
   * the names match exactly, or if use_full_name parameter is not set
   * up to the '@' separator.
   */
  if ((userlen == client_name_buf.length) ||
      (!use_full_name 
       && userlen < client_name_buf.length 
       && client_name_str[userlen] == '@'))
  { 
    if (strncmp(client_name_str, user, userlen) == 0)
    {
      rc= CR_OK;
    }
    else 
    {
      rc= CR_ERROR;
      my_printf_error(ER_UNKNOWN_ERROR, 
		      "GSSAPI name mismatch, actual name %.*s",
		      MYF(0),(int)client_name_buf.length,client_name_str);
    }
  }
  gss_release_buffer(&minor, &client_name_buf);
  

cleanup:
  if (ctxt != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);
  if (cred != GSS_C_NO_CREDENTIAL)
    gss_release_cred(&minor, &cred);

  return(rc);
}
