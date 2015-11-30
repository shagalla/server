#include <windows.h>
#include <stdio.h>
void sspi_errmsg(int err, const char *msg, char *buf, size_t size)
{
  if (err != 0)
  {
    char system_msg[1024];
    if (FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
      err, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
      system_msg, sizeof(system_msg), NULL) == 0)
    {
      _snprintf(buf, size, "%s - SSPI error 0x%x", msg, err);
    }
    else
    {
      /* Trim trailing \n\r*/
      char *p; 
      for(p= system_msg + strlen(system_msg);p > system_msg && (*p == '\n' || *p=='\r');p--)
        *p= 0;
      _snprintf(buf, size, "%s - SSPI error 0x%x : %s)", msg, err, system_msg);
    }
  }
  else
  {
    _snprintf(buf,size, "%s", msg);
  }
}