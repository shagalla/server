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

  This is the client side implementation.
*/
#include <string.h>
#include <stdarg.h>
#include <mysqld_error.h>
#include <mysql/client_plugin.h>
#include <mysql.h>
#include <stdio.h>

extern int auth_client(const char *target_name,
                       const char *mech, 
                       MYSQL *mysql,
                       MYSQL_PLUGIN_VIO *vio);

static void parse_server_packet(char *packet, int packet_len, char **spn, char **mech)
{
  size_t spn_len= strlen(packet);
  *spn= packet;
  if (spn_len == packet_len - 1)
  {
    /* mechanism is either not included into packet, */
    *mech = 0;
  }
  else 
  {
    *mech = packet + spn_len + 1;
  }
}

/**
  Set client error message.
 */
void log_client_error(MYSQL *mysql,  const char *format, ...)
{
  NET *net= &mysql->net;
  va_list args;

  net->last_errno= ER_UNKNOWN_ERROR;
  va_start(args, format);
  vsnprintf(net->last_error, sizeof(net->last_error) - 1,
          format, args);
  va_end(args);
  memcpy(net->sqlstate, "HY000", sizeof(net->sqlstate));
}

/**
  The main client function of the GSSAPI plugin.
 */
static int gssapi_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  int packet_len;
  unsigned char *packet;
  char *spn;
  char *mech;

  /* read from server for service principal name */
  packet_len= vio->read_packet(vio, (unsigned char **) &packet);
  if (packet_len < 0)
  {
    return CR_ERROR;
  }
  parse_server_packet(packet, packet_len, &spn, &mech);
  return auth_client(spn, mech, mysql, vio);
}


/* register client plugin */
mysql_declare_client_plugin(AUTHENTICATION)
  "auth_gssapi_client",
  "Shuang Qiu",
  "GSSAPI/SSPI based authentication",
  {0, 1, 0},
  "BSD",
  NULL,
  NULL,
  NULL,
  NULL,
  gssapi_auth_client
mysql_end_client_plugin;
