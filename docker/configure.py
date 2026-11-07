"""Validate container options and render the bundled Nginx configuration."""
import argparse
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit


CONFIG_PATH = '/tmp/ntwa-nginx.conf'
AUTH_PATH = '/tmp/ntwa.htpasswd'
HEALTH_SOCKET = '/tmp/ntwa-health.sock'
ROOT = Path(__file__).resolve().parents[1]


def csv(value):
    return [item.strip() for item in value.split(',') if item.strip()]


def hostname(value):
    value = value.strip().lower()
    if '%' in value:
        raise ValueError('Scoped IPv6 hosts are not supported')
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?', value):
            raise ValueError(f'Invalid host: {value}')
        return value


def boolean(value):
    if value.strip().lower() in {'1', 'true', 'yes', 'on'}:
        return True
    if value.strip().lower() in {'0', 'false', 'no', 'off', ''}:
        return False
    raise ValueError('Invalid NTWA_PUBLIC_MODE: use true or false')


def listen_addresses(values):
    result = []
    for raw in values:
        raw = raw.strip()
        if '%' in raw:
            raise ValueError('Scoped IPv6 listeners are not supported')
        if re.fullmatch(r'[0-9]+', raw):
            hosts, port_text = ['0.0.0.0', '::'], raw
        elif raw.startswith('['):
            match = re.fullmatch(r'\[([^\]]+)\]:([0-9]+)', raw)
            if not match:
                raise ValueError(f'Invalid listen address: {raw}')
            hosts, port_text = [str(ipaddress.IPv6Address(match[1]))], match[2]
        else:
            match = re.fullmatch(r'([^:]+):([0-9]+)', raw)
            if not match:
                raise ValueError(f'Invalid listen address: {raw}')
            host = match[1]
            hosts = ['127.0.0.1' if host == 'localhost' else str(ipaddress.IPv4Address(host))]
            port_text = match[2]
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError(f'Port out of range: {port}')
        for host in hosts:
            address = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            if address not in result:
                result.append(address)
    return result


def endpoint(address):
    host, port = address.rsplit(':', 1)
    return ipaddress.ip_address(host.strip('[]')), int(port)


def check_listeners(http, https):
    # Gunicorn owns this endpoint, independently of the external listeners.
    endpoints = [('upstream', '127.0.0.1:35000')]
    for protocol, addresses in [('HTTP', http), ('HTTPS', https)]:
        for address in addresses:
            host, port = endpoint(address)
            for other_protocol, other_address in endpoints:
                other_host, other_port = endpoint(other_address)
                if host.version == other_host.version and port == other_port and (
                        host == other_host or host.is_unspecified or other_host.is_unspecified):
                    raise ValueError(f'Listen conflict: {protocol} {address} and {other_protocol} {other_address}')
            endpoints.append((protocol, address))


def readable_file(value, label):
    if not value:
        return ''
    if any(char in value for char in '\r\n\x00$'):
        raise ValueError(f'Invalid {label} path')
    path = Path(value).resolve()
    if any(char in str(path) for char in '\r\n\x00$'):
        raise ValueError(f'Invalid {label} path')
    try:
        with path.open('rb') as stream:
            stream.read(1)
        if not path.is_file():
            raise OSError('Not a regular file')
    except OSError as error:
        raise ValueError(f'{label} must be a readable file: {path}') from error
    return str(path)


@dataclass
class Config:
    http_listens: list
    https_listens: list
    server_names: list
    tls_cert: str
    tls_key: str
    redirect_http_to: str
    base_path: str
    auth_user: str
    auth_password_file: str
    public_mode: bool
    trusted_hosts: list
    trusted_proxies: list
    check_config: bool

    def environment(self, environ):
        return dict(environ, NTWA_PUBLIC_MODE=str(self.public_mode).lower(),
                    NTWA_TRUSTED_HOSTS=','.join(self.trusted_hosts),
                    NTWA_TRUSTED_PROXIES=','.join(self.trusted_proxies))


def parse_config(argv, environ):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('legacy_listen', nargs='?', help='Legacy HTTP listen address (default: 30080)')
    for name in ('listen', 'https-listen', 'server-name'):
        parser.add_argument('--' + name, action='append', help='Repeat for multiple values; env NTWA_' + name.upper().replace('-', '_'))
    for name in ('tls-cert', 'tls-key', 'redirect-http-to', 'base-path', 'auth-user',
                 'auth-password-file', 'trusted-hosts', 'trusted-proxies'):
        parser.add_argument('--' + name, help='Env NTWA_' + name.upper().replace('-', '_'))
    parser.add_argument('--public-mode', action=argparse.BooleanOptionalAction, default=None,
                        help='Enable public Looking Glass restrictions (env NTWA_PUBLIC_MODE)')
    parser.add_argument('--check-config', action='store_true', help='Validate options and run nginx -t, then exit')
    args = parser.parse_args(argv)

    def value(name, default=''):
        option = getattr(args, name)
        return option if option is not None else environ.get('NTWA_' + name.upper(), default)

    def values(name, default=''):
        option = getattr(args, name)
        return option if option is not None else csv(environ.get('NTWA_' + name.upper(), default))

    if args.legacy_listen is not None and args.listen is not None:
        raise ValueError('Legacy listen address cannot be combined with --listen')
    http = listen_addresses([args.legacy_listen] if args.legacy_listen is not None else values('listen', '30080'))
    if not http:
        raise ValueError('At least one HTTP listen address is required')
    cert = readable_file(value('tls_cert'), 'TLS certificate')
    key = readable_file(value('tls_key'), 'TLS key')
    if bool(cert) != bool(key):
        raise ValueError('TLS certificate and key must be provided together')
    https = listen_addresses(values('https_listen', '30443' if cert else ''))
    if https and not cert:
        raise ValueError('HTTPS listeners require --tls-cert and --tls-key')
    if cert and not https:
        raise ValueError('TLS requires at least one HTTPS listen address')
    check_listeners(http, https)

    names = list(dict.fromkeys(hostname(item) for item in values('server_name')))
    hosts = list(dict.fromkeys(hostname(item) for item in csv(value('trusted_hosts'))))
    if args.trusted_hosts is None and not environ.get('NTWA_TRUSTED_HOSTS'):
        hosts = names.copy()
    proxy_values = csv(value('trusted_proxies'))
    if any('%' in item for item in proxy_values):
        raise ValueError('Scoped IPv6 trusted proxies are not supported')
    proxies = list(dict.fromkeys(str(ipaddress.ip_network(item, strict=False)) for item in proxy_values))
    base = value('base_path', '/')
    if not base.startswith('/') or not re.fullmatch(r'/[A-Za-z0-9_.~/-]*', base):
        raise ValueError('Base path must be an absolute URL path with unescaped ASCII segments')
    if base != '/' and any(part in {'', '.', '..'} for part in base.strip('/').split('/')):
        raise ValueError('Base path contains an empty or relative segment')
    if '//' in base:
        raise ValueError('Base path contains an empty segment')
    base = base.rstrip('/') + '/' if base != '/' else '/'

    redirect = value('redirect_http_to')
    if redirect:
        origin = urlsplit(redirect)
        if (origin.scheme != 'https' or not origin.hostname or origin.username is not None
                or origin.password is not None or origin.path not in {'', '/'} or origin.query or origin.fragment
                or '?' in redirect or '#' in redirect or not https):
            raise ValueError('HTTP redirect requires TLS and an HTTPS origin without path, credentials, query or fragment')
        host = hostname(origin.hostname)
        port = origin.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError('Invalid redirect port')
        # Rebuild from validated components; never interpolate raw URL text into Nginx.
        redirect = 'https://' + (f'[{host}]' if ':' in host else host) + (f':{port}' if port is not None else '')

    user = value('auth_user')
    password_file = readable_file(value('auth_password_file'), 'Auth password')
    if bool(user) != bool(password_file):
        raise ValueError('Auth user and password file must be provided together')
    if user and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', user):
        raise ValueError('Invalid auth user')
    public = args.public_mode if args.public_mode is not None else boolean(environ.get('NTWA_PUBLIC_MODE', ''))
    return Config(http, https, names, cert, key, redirect, base, user, password_file, public,
                  hosts, proxies, args.check_config)


def nginx_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$') + '"'


def render_nginx(config, template):
    base = config.base_path
    api_limits = 'limit_req zone=api_ip burst=20 nodelay; limit_req zone=api_global burst=120 nodelay; limit_req_status 429;' if config.public_mode else ''
    sse_limits = 'limit_req zone=sse_open burst=4 nodelay; limit_conn sse_ip 4; limit_conn sse_global 32; limit_req_status 429; limit_conn_status 429;' if config.public_mode else ''
    locations = f'''
        location ~ ^{re.escape(base)}api/traces/[^/]+/events$ {{
            {sse_limits}
            proxy_buffering off;
            rewrite ^{re.escape(base)}(.*)$ /$1 break;
            proxy_pass http://app;
        }}
        location {base}api/ {{
            {api_limits}
            proxy_pass http://app/api/;
        }}
        location {base} {{
            proxy_pass http://app/;
        }}
        location = {base}favicon.ico {{
            proxy_pass http://app/assets/favicon.ico;
        }}
'''
    if base != '/':
        locations += f'''
        location = {base[:-1]} {{ return 301 {base}$is_args$args; }}
        location / {{ return 404; }}
'''
    auth = f'auth_basic "NextTrace"; auth_basic_user_file {AUTH_PATH};' if config.auth_user else ''
    names = ' '.join(config.server_names) or '_'

    def server(listens, tls=False, redirect=False):
        directives = '\n'.join(f'listen {address}' + (' ssl' if tls else '') + ';' for address in listens)
        certificate = f'ssl_certificate {nginx_quote(config.tls_cert)};\nssl_certificate_key {nginx_quote(config.tls_key)};' if tls else ''
        content = f'return 308 {config.redirect_http_to}$request_uri;' if redirect else auth + '\n' + locations
        return f'server {{\n{directives}\nserver_name {names};\n{certificate}\n{content}\n}}'

    servers = server(config.http_listens, redirect=bool(config.redirect_http_to))
    if config.https_listens:
        servers += '\n' + server(config.https_listens, tls=True)
    health_host = config.trusted_hosts[0] if config.trusted_hosts else 'localhost'
    if ':' in health_host:
        health_host = f'[{health_host}]'
    servers += f'''
    server {{
        listen unix:{HEALTH_SOCKET};
        server_name localhost;
        access_log off;
        location = /healthz {{
            proxy_set_header Host {nginx_quote(health_host)};
            proxy_pass http://app/healthz;
        }}
        location / {{ return 404; }}
    }}
'''
    return (template.replace('__TRUSTED_PROXY_DIRECTIVES__', '\n'.join(f'set_real_ip_from {network};' for network in config.trusted_proxies))
            .replace('__TRUSTED_PROXY_RANGES__', '\n'.join(f'{network} 1;' for network in config.trusted_proxies))
            .replace('__SERVERS__', servers))


def write_auth(config):
    if not config.auth_user:
        return
    password = Path(config.auth_password_file).read_text().removesuffix('\n')
    if not password or any(char in password for char in '\r\n\x00') or len(password.encode()) > 72:
        raise ValueError('Auth password must be one nonempty line of at most 72 UTF-8 bytes')
    hashed = subprocess.run(['htpasswd', '-niB', config.auth_user], input=password + '\n',
                            text=True, capture_output=True)
    if hashed.returncode:
        raise ValueError('Could not generate Basic Auth password hash')
    with open(AUTH_PATH, 'w', opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(hashed.stdout)


def main():
    try:
        config = parse_config(sys.argv[1:], os.environ)
        if config.public_mode and (len(os.environ.get('NTWA_SECRET_KEY', '')) < 32 or not config.trusted_hosts):
            raise ValueError('Public mode requires NTWA_SECRET_KEY (at least 32 characters) and trusted hosts')
        os.umask(0o077)
        write_auth(config)
        Path(CONFIG_PATH).write_text(render_nginx(config, Path('/etc/nginx/nginx.conf.template').read_text()))
        subprocess.run(['nginx', '-e', 'stderr', '-t', '-c', CONFIG_PATH], check=True)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Container configuration error: {error}') from error
    if not config.check_config:
        os.execvpe('/bin/bash', ['bash', str(ROOT / 'docker/supervise.sh')], config.environment(os.environ))


if __name__ == '__main__':
    main()
