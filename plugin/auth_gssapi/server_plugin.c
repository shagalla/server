/* Copyright (c) 2015, Shuang Qiu
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

/**
  @file

  Kerberos server authentication plugin

  kerberos_server is a general purpose server authentication plugin, it
  authenticates user against Kerberos principal.

  This is the server side implementation.
*/
#include <my_sys.h>
#include <mysqld_error.h>
#include <mysql/plugin_auth.h>
#include <mysql.h>
#include "server_plugin.h"


#define TARGET_NAME_MAX 256
#define MECH_NAME_MAX 30

/* First packet sent from server to client, contains srv_target_name\0mech\0 */
static char first_packet[TARGET_NAME_MAX + MECH_NAME_MAX +2];
static int  first_packet_len;

/* 
 Target name in GSSAPI/SSPI , for Kerberos it is service principal name
 (often user principal name of the server user will work)
*/
char *srv_target_name;
char *srv_keytab_path;
char *srv_mech_name="";
char  *srv_keytab_path;
unsigned long srv_mech_index;
static const char* mech_names[] = {
  "Kerberos",
  "Negotiate",
  NULL
};

/**
  The main server function of the GSSAPI plugin.
 */
static int gssapi_auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *auth_info)
{
  int use_full_name;
  const char *user;
  int user_len;
 
  /* Send first packet with target name and mech name */
  if (vio->write_packet(vio, first_packet, first_packet_len))
  {
    return CR_ERROR;
  }
  
  /* Figure out whether to use full name (as given in IDENTIFIED AS clause)
   * or just short username auth_string
   */
  if (auth_info->auth_string_length > 0)
  {
    use_full_name= 1;
    user= auth_info->auth_string;
    user_len= auth_info->auth_string_length;
  }
  else
  {
    use_full_name= 0;
    user= auth_info->user_name;
    user_len= auth_info->user_name_length;
  }
  
  return auth_server(vio, user, user_len, use_full_name);
}

static int initialize_plugin(void *unused)
{
  srv_mech_name = (char*)mech_names[srv_mech_index];
  int rc = plugin_init();
  if (rc)
    return rc;

  strcpy(first_packet, srv_target_name);
  strcpy(first_packet + strlen(srv_target_name) + 1,srv_mech_name);
  first_packet_len = strlen(srv_target_name) + strlen(srv_mech_name) + 2;

  return 0;
}

static int deinitialize_plugin(void *unused)
{
  return plugin_deinit();
}

static TYPELIB mech_name_typelib = {
  array_elements(mech_names) - 1,
  "mech_name_typelib",
  mech_names,
  NULL
};
/* system variable */
static MYSQL_SYSVAR_STR(keytab_path, srv_keytab_path,
                        PLUGIN_VAR_RQCMDARG|PLUGIN_VAR_READONLY,
                        "Keytab file path (Kerberos)",
                        NULL, 
                        NULL,
                        "");
static MYSQL_SYSVAR_STR(target_name, srv_target_name,
                        PLUGIN_VAR_RQCMDARG|PLUGIN_VAR_READONLY,
                        "GSSAPI target name - service principal name for Kerberos authentication.",
                        NULL, 
                        NULL,
                        "");

static MYSQL_SYSVAR_ENUM(mech_name, srv_mech_index,
                        PLUGIN_VAR_RQCMDARG|PLUGIN_VAR_READONLY,
                        "GSSAPI mechanism : either Kerberos or Negotiate",
                        NULL, 
                        NULL,
                        1,&mech_name_typelib);

static struct st_mysql_sys_var *system_variables[]= {
  MYSQL_SYSVAR(target_name),
  MYSQL_SYSVAR(mech_name),
  MYSQL_SYSVAR(keytab_path),
  NULL
};

/* Register authentication plugin */
static struct st_mysql_auth server_handler= {
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "auth_gssapi_client",
  gssapi_auth
};

maria_declare_plugin(gssapi_server)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &server_handler,
  "gssapi",
  "Shuang Qiu",
  "Plugin for GSSAPI/SSPI based authentication.",
  PLUGIN_LICENSE_BSD,
  initialize_plugin,
  deinitialize_plugin,                   /* destructor */
  0x0100,                                /* version */
  NULL,                                  /* status variables */
  system_variables,                      /* system variables */
  "1.0",
  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL  
}
maria_declare_plugin_end;

