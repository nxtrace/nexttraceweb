import re

INVALID_PARAM_PATTERN = re.compile(r'[&;<>"\'()|\[\]{}$#!%*+=]')


def build_mtr_json_command(nexttrace_path, params, flavor='nexttrace'):
    if flavor not in ('nexttrace', 'nexttrace-tiny', 'ntr'):
        raise ValueError('Unsupported NextTrace flavor: ' + str(flavor))
    # ntr is MTR-only and does not register the --mtr switch.
    mode = [] if flavor == 'ntr' else ['--mtr']
    return [nexttrace_path, *params, *mode, '--json']


def build_process_env(source_env, public=False):
    if not public:
        env = dict(source_env)
        env.pop('NEXTTRACE_UNINTERRUPTED', None)
        return env
    # Probes need runtime/GeoIP configuration, never Flask secrets or proxy credentials.
    runtime = {'PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'SSL_CERT_FILE', 'SSL_CERT_DIR'}
    nexttrace = {'NEXTTRACE_HOSTPORT', 'NEXTTRACE_POWPROVIDER', 'NEXTTRACE_DATAPROVIDER', 'NEXTTRACE_TOKEN', 'NEXTTRACE_API_V4_TOKEN'}
    return {key: value for key, value in source_env.items() if key in runtime or key in nexttrace}
