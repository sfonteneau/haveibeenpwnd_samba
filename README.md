Use haveibeenpwnd  for check password script in samba

install haveibeenpwnd with command : pip install haveibeenpwnd

Add script in /scripts

Add in smb.conf :

check password script = python /scripts/check_password_hibpwnd.py

Restart Samba
