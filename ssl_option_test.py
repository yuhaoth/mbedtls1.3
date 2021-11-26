
from os import stat


class TLSProgram:
    def __init__(self, cmd, is_server=False):
        self.is_server = is_server
        assert '{SRV_PORT}' in cmd
        self._cmd = cmd
    def __str__(self):
        return '"{}"'.format(self._cmd)

class SSLOptionTest:
    # pylint: disable-next=too-many-arguments
    def __init__(self, name, srv_cmd, cli_cmd, pre_checks, post_checks, pxy_cmd=None, info=None):
        self._name = name
        self._srv_cmd = srv_cmd
        self._cli_cmd = cli_cmd
        self._pxy_cmd = pxy_cmd
        self._pre_checks = pre_checks
        self._post_checks = post_checks
        self._srv = TLSProgram(srv_cmd,is_server=True)
        self._cli = TLSProgram(cli_cmd,is_server=False)
        self._pxy = TLSProgram(pxy_cmd,is_server=True) if pxy_cmd else None
        self._info = info

    def bash_cmd(self):
        pass

    @property
    def name(self):
        return self._name
def divide_ssl_opt(filename='tests/ssl-opt.sh'):
    # divide ssl-opt into 3 groups
    with open(filename,'r') as f:
        status='header'
        for line in f:
            if line.startswith('# test_cases'):
                if line.endswith('ON\n'):
                    status = 'test_cases'
                elif line.endswith('OFF\n'):
                    status='header'
                elif line.endswith('TAIL\n'):
                    status='tail'
            if status == 'header':
                yield line,'\n','\n'
            elif status == 'test_cases':
                yield '\n',line,'\n'
            elif status == 'tail':
                yield '\n','\n',line


with open('header.sh','w') as a, open('test_cases.sh','w') as b, open('tail.sh','w') as c:
    for header,test_cases,tail in divide_ssl_opt():
        a.write(header)
        b.write(test_cases)
        c.write(tail)
# header,test_cases,tail = a,b,c




