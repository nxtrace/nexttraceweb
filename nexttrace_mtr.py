import re
import shlex
import subprocess
from functools import lru_cache

FULL_MTR_RAW_FIXED_ARGS = ('--mtr', '--raw', '--map')
NTR_RAW_FIXED_ARGS = ('--raw',)
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
    return [nexttrace_path] + param_list + list(resolve_mtr_raw_fixed_args(nexttrace_path))


def build_process_env(source_env):
    env = dict(source_env)
    env.pop('NEXTTRACE_UNINTERRUPTED', None)
    return env


@lru_cache(maxsize=None)
def resolve_mtr_raw_fixed_args(nexttrace_path):
    help_output = read_help_output(nexttrace_path)
    if not help_output:
        return FULL_MTR_RAW_FIXED_ARGS

    supports_mtr = '--mtr' in help_output or '-t  --mtr' in help_output
    supports_map = '--map' in help_output or '-M  --map' in help_output
    supports_raw = '--raw' in help_output

    if supports_mtr and supports_map:
        return FULL_MTR_RAW_FIXED_ARGS
    if supports_raw:
        return NTR_RAW_FIXED_ARGS
    return FULL_MTR_RAW_FIXED_ARGS


def read_help_output(nexttrace_path):
    try:
        result = subprocess.run(
            [nexttrace_path, '--help'],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
    except Exception:
        return ''
    return result.stdout or ''


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
