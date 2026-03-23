import re
import shlex

MTR_RAW_FIXED_ARGS = ('--mtr', '--raw', '--map')
MTR_RAW_FIELD_COUNT = 12
MTR_RAW_IGNORED_PREFIXES = (
    '[NextTrace API]',
    'NextTrace v',
    'IP Geo Data Provider:',
)
INVALID_PARAM_PATTERN = re.compile(r'[&;<>"\'()|\[\]{}$#!%*+=]')


def build_mtr_raw_command(nexttrace_path, params):
    if isinstance(params, str):
        param_list = shlex.split(params)
    else:
        param_list = list(params)
    return [nexttrace_path] + param_list + list(MTR_RAW_FIXED_ARGS)


def build_process_env(source_env):
    env = dict(source_env)
    env.pop('NEXTTRACE_UNINTERRUPTED', None)
    return env


def parse_mtr_raw_line(line):
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith(MTR_RAW_IGNORED_PREFIXES):
        return None
    if not re.match(r'^\d+\|', stripped):
        return None

    fields = stripped.split('|')
    if len(fields) != MTR_RAW_FIELD_COUNT:
        return None

    ttl = _parse_int(fields[0])
    if ttl is None:
        return None

    raw_ip = fields[1].strip()
    ip = '' if raw_ip == '*' else raw_ip
    host = fields[2].strip()
    rtt_ms = _parse_float(fields[3])

    return {
        'ttl': ttl,
        'success': raw_ip != '*' and bool(ip or host),
        'ip': ip,
        'host': host,
        'rtt_ms': rtt_ms,
        'asn': fields[4].strip(),
        'country': fields[5].strip(),
        'prov': fields[6].strip(),
        'city': fields[7].strip(),
        'district': fields[8].strip(),
        'owner': fields[9].strip(),
        'lat': _parse_float(fields[10]),
        'lng': _parse_float(fields[11]),
    }


def _parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
