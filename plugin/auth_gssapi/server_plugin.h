/* Plugin variables*/
#include <mysql/plugin_auth.h>
extern char *srv_target_name;
extern char *srv_mech_name;

/*
  Check, with GSSAPI/SSPI username of logged on user.

  Depending on use_full_name parameter, compare either full name 
  (principal name like user@real), or local name (first component)
*/
int auth_server(MYSQL_PLUGIN_VIO *vio, const char *username, int  use_full_name);