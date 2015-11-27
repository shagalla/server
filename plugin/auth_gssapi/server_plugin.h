/* Plugin variables*/
#include <mysql/plugin_auth.h>
extern char *srv_target_name;
extern char *srv_mech_name;
extern char *srv_keytab_path;
/*
  Check, with GSSAPI/SSPI username of logged on user.

  Depending on use_full_name parameter, compare either full name 
  (principal name like user@real), or local name (first component)
*/
int plugin_init();
int plugin_deinit();

int auth_server(MYSQL_PLUGIN_VIO *vio, const char *username, int  username_len, int use_full_name);
