Use check password script
===========================

Block password change if it appears in haveibeenpwnd

install haveibeenpwnd with command : pip install haveibeenpwnd

Add script in /scripts

Add in smb.conf :

check password script = python /scripts/check_password_hibpwnd.py

Enable complexity :

samba-tool domain passwordsettings set --complexity=on

Restart Samba


Test
-----------------

python3 /scripts/check_password_hibpwnd.py

Enter test password

Audit Existing Password
==============================

List user hashes then test them with haveibeenpwnd

Test
-----------------

apt-get install python3-pycryptodome
python3 /scripts/audit_password.py
