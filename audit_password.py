#!/usr/bin/python
# -*- coding: utf-8 -*-
import getpass
import ldb
import optparse
import samba.getopt as options
import requests
import sys
import argparse
from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--fileleak', dest='fileleak')
parser.add_argument('--ldapfilter', dest='ldapfilter', default='(&(objectClass=user)(!(objectClass=computer)))',help='Ldap filter')
args = parser.parse_args()

smbconf="/etc/samba/smb.conf"
parser = optparse.OptionParser(smbconf)
sambaopts = options.SambaOptions(parser)
lp = sambaopts.get_loadparm()
creds = Credentials()
creds.guess(lp)

samdb = SamDB( session_info=system_session(),credentials=creds, lp=lp)

dict_hash = {}

for user in samdb.search(base=samdb.get_default_basedn(), expression=r"(&(objectClass=user)%s)" % args.ldapfilter):

    passwordattr = 'unicodePwd'
    password = samdb.search(samdb.get_default_basedn(),expression="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr])[0]
    if not passwordattr in password:
        continue

    hashnt = password[passwordattr][0].hex().upper()

    if hashnt in dict_hash:
        dict_hash[hashnt].append(user['samAccountName'][0].decode('utf-8'))
    else:
        dict_hash[hashnt] = [user['samAccountName'][0].decode('utf-8')]

for entry in dict_hash:
    if len(dict_hash[entry]) > 1:
        print('Account with the same password : %s' % (dict_hash[entry]))

if args.fileleak:
    file_name_ihbpp = open(args.fileleak)
    while True:
        data = file_name_ihbpp.readlines(10000000)
        if not data:
            break
        for d in data:
            nthash = d.split(':',1)[0]
            leak_nb = d.split(':',1)[1]
            if nthash in dict_hash:
                print('sAMAccountName %s with %s nthash. This password has been seen %s times before' % (dict_hash[nthash],nthash, leak_nb))
else:
    for nthash in dict_hash:
        result = requests.get(r"https://api.pwnedpasswords.com/range/%s?mode=ntlm" % nthash[:5])
        resultihb = {h.split(':')[0]:h.split(':')[1] for h in  result.content.decode('utf-8').split('\r\n')}
        if nthash[5:] in resultihb:
            print('sAMAccountName %s with %s nthash. This password has been seen %s times before' % (dict_hash[nthash],nthash,resultihb[nthash[5:]]))
