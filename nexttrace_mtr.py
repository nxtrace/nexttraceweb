import re

INVALID_PARAM_PATTERN = re.compile(r'[&;<>"\'()|\[\]{}$#!%*+=]')


def build_mtr_json_command(nexttrace_path, params, flavor='nexttrace'):
    if flavor not in ('nexttrace', 'nexttrace-tiny', 'ntr'):
        raise ValueError('Unsupported NextTrace flavor: ' + str(flavor))
    # ntr is MTR-only and does not register the --mtr switch.
    mode = [] if flavor == 'ntr' else ['--mtr']
    return [nexttrace_path, *params, *mode, '--json']


def build_process_env(source_env):
    env = dict(source_env)
    env.pop('NEXTTRACE_UNINTERRUPTED', None)
    return env
