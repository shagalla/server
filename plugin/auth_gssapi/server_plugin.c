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


#define TARGET_NAME_MAX 256
#define MECH_MAX 30

/* First packet sent from server to client, contains target_name\0mech\0 */
static char first_packet[TARGET_NAME_MAX + MECH_MAX +2];
static int  first_packet_len;

/* 
 Target name in GSSAPI/SSPI , for Kerberos it is service principal name
 (often user principal name of the server user will work)
*/
static char  *target_name;

/*
  Mechanism used by GSSAPI, as readable string
  Either "Kerberos" or "Negotiate" or empty string
*/
static char *mech="";
unsigned long mech_index;
static const char* mech_names[] = {
	"Kerberos",
	"Negotiate",
	NULL
};

extern int get_client_name(char *target_name, 
  char *mech, 
  MYSQL_PLUGIN_VIO *vio, 
  char *client_name,
  size_t client_name_len,
  int  use_full_client_name);

/**
  The main server function of the GSSAPI plugin.
 */
static int gssapi_auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *auth_info)
{
  int rc;
  int use_full_name= (auth_info->auth_string_length > 0);
  const char *requested_name = use_full_name?auth_info->auth_string:auth_info->user_name;
  char *client_name= auth_info->external_user;
  size_t client_name_len= sizeof(auth_info->external_user);

  /* Send first packet with target name and mech */
  if (vio->write_packet(vio, first_packet, first_packet_len))
  {
    return CR_ERROR;
  }
 
  /* 
     Retrieve client name, either single component or fully qualified
  */
  rc = get_client_name(target_name, mech, vio, client_name,client_name_len,use_full_name);
  if(rc != CR_OK)
    return rc;

#ifdef _WIN32
  rc= _stricmp(client_name,requested_name) == 0 ? CR_OK : CR_ERROR;
#else
  rc= strcmp(client_name, requested_name) == 0 ? CR_OK : CR_ERROR;
#endif

  if(rc != CR_OK)
  {
    my_printf_error(ER_UNKNOWN_ERROR,"GSSAPI name mismatch, got %s",MYF(0),client_name);
  }
  return rc;
}

static int initialize_plugin(void *unused)
{
  mech = (char*)mech_names[mech_index];
  strcpy(first_packet, target_name);
  strcpy(first_packet + strlen(target_name) + 1,mech);
  first_packet_len = strlen(target_name) + strlen(mech) + 2;
  return 0;
}




static TYPELIB mech_name_typelib = {
	array_elements(mech_names) - 1,
	"mech_names_typelib",
	mech_names,
  NULL
};
/* system variable */
static MYSQL_SYSVAR_STR(target_name, target_name,
                        PLUGIN_VAR_RQCMDARG|PLUGIN_VAR_READONLY,
                        "GSSAPI target name - service principal name for Kerberos authentication.",
                        NULL, 
                        NULL,
                        "");
static MYSQL_SYSVAR_ENUM(mech, mech_index,
                        PLUGIN_VAR_RQCMDARG|PLUGIN_VAR_READONLY,
                        "GSSAPI mechanism : either Kerberos or Negotiate",
                        NULL, 
                        NULL,
                        1,&mech_name_typelib);

static struct st_mysql_sys_var *system_variables[]= {
  MYSQL_SYSVAR(target_name),
#ifdef _WIN32
  MYSQL_SYSVAR(mech),
#endif
  NULL
};

/* register Kerberos authentication plugin */
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
  NULL,                                  /* destructor */
  0x0100,                                /* version */
  NULL,                                  /* status variables */
  system_variables,                      /* system variables */
  "GSSAPI/SSPI authentication plugin",
  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL  
}
maria_declare_plugin_end;

