#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import rsa
import string
import textwrap
import base64
import re
import urllib
import urllib2
import ssl
import cookielib

hosts=["ap_ip_address","ap_ip_address"]
apass="airstation_pass=your_password"

sid=""
snum=""
mod=""
enp=""
opener=""

def rebootBuf(str):
  global sid
  global snum
  req = urllib2.Request \
     ("https://%s/cgi-bin/cgi?req=inp&res=waiting_page.html" % (str))
  req.add_header('Content-Type', 'appliation/x-www-form-urlencoded')
  urstr = u'再起動'
  rstr  = urstr.encode('euc-jp')
  params = urllib.urlencode({'reboot': rstr, \
          'sWebSessionnum': snum, 'sWebSessionid': sid})
  req.add_data(params)
  try:
    ret = opener.open(req)
  except urllib2.URLError as e:
    print "Cannot access to ap"
    print(e.reason)
    return 0
  else:
    print "send to %s a reboot command..." % (str)
    ret.close()
    return 1
  

def loginBuf(str, enc):
  global sid
  global snum
  req = urllib2.Request \
     ("https://%s/cgi-bin/cgi?req=inp&res=login.html" % (str))
  req.add_header('Content-Type', 'appliation/x-www-form-urlencoded')
  params = urllib.urlencode({'lang': 'jp', 'airstation_uname': 'admin', \
          'encrypted': enc, 'sWebSessionnum': snum, 'sWebSessionid': sid})
  req.add_data(params)
  try:
    ret = opener.open(req)
  except urllib2.URLError as e:
    print "Cannot access to ap"
    print(e.reason)
    return 0
  else:
    flag=0
    lre = re.compile("(LOGIN)")
    for row in ret:
      m = lre.search(row)
      if m is not None:
        flag=1
    ret.close()
    if flag == 1:
      print "Not Login"
      return 0
  return 1
  
def logoutBuf(str):
  req = urllib2.Request \
           ("https://%s/cgi-bin/cgi?req=twz&frm=logout.html" % (str))
  try:
    ret = opener.open(req, timeout=10)
  except urllib2.URLError as e:
    print "Cannot access to ap"
    print(e.reason)
    return 0
  else:
    ret.read()
    ret.close()
  return 1

def getParamBuf(str):
  global mod
  global enp
  global sid
  global snum
  req = urllib2.Request("https://%s/cgi-bin/cgi?req=twz" % (str))
  try:
    ret = opener.open(req, timeout=10)
  except urllib2.URLError as e:
    print "Cannot access to ap"
    print(e.reason)
    return 0
  else:
    ire = re.compile \
          ("sWebSessionnum value=([0-9]+).+sWebSessionid value=([\-0-9]+)")
    ere = re.compile("var exponent = \"([0-9]+)\"")
    mre = re.compile("var modulus = \"([0-9A-F]+)\"")
    for row in ret:
      m = ire.search(row)
      if m is not None:
        snum = m.group(1)
        sid  = m.group(2)
      m = mre.search(row)
      if m is not None:
        mod = m.group(1)
      m = ere.search(row)
      if m is not None:
        enp = m.group(1)
    ret.close()
    if snum == "" or sid == "" or mod == "" or enp == "":
      print "Cannot get parameters"
      return 0
  return 1

def rsa_encrypt(str):
  global mod
  global enp
  lnum=68
  n,e=string.atol(mod,16),string.atol(enp,10);

  bob_pub=rsa.PublicKey(n,e)

  crypt=rsa.encrypt(str,bob_pub)
  encode=base64.standard_b64encode(crypt)

  wrapen=textwrap.fill(encode)
  return wrapen


if __name__ == '__main__':
  ssl._create_default_https_context = ssl._create_unverified_context
  args = sys.argv
  if len(args) == 2:
    cnt = 0
    while cnt < len(hosts):
      if hosts[cnt] == args[1]:
        break;
      cnt += 1
    if cnt == len(hosts):
      print "Cannot find for %s" % (args[1])
      sys.exit(1)
    else:
      cj=cookielib.CookieJar()
      opener=urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
      logoutBuf(args[1])
      if getParamBuf(args[1]) == 0:
        sys.exit(1)
      enc = rsa_encrypt(apass)
      if loginBuf(args[1], enc) == 0:
        sys.exit(1)
      if rebootBuf(args[1]) == 0:
        sys.exit(1)
  else:
    print "usage: apReboot.py [AP]"
    sys.exit(1)
  sys.exit(0)

