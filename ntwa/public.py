"""Server-enforced policy for an anonymous public Looking Glass."""
import ipaddress
import logging
import os
import socket
from .config import PayloadError, build_trace_params, env_bool, parse_positive_float, parse_positive_int


def networks(value):
    return tuple(ipaddress.ip_network(item.strip(), strict=False) for item in value.split(',') if item.strip())


def configure_public(config):
    enabled = env_bool('NTWA_PUBLIC_MODE', False)
    config.update(
        NTWA_PUBLIC_MODE=enabled,
        NTWA_PUBLIC_DENY_CIDRS=os.environ.get('NTWA_PUBLIC_DENY_CIDRS', ''),
        NTWA_PUBLIC_DEVICE=os.environ.get('NTWA_PUBLIC_DEVICE', '').strip(),
        NTWA_PUBLIC_TCP_PORTS=os.environ.get('NTWA_PUBLIC_TCP_PORTS', '80,443'),
        NTWA_PUBLIC_UDP_PORTS=os.environ.get('NTWA_PUBLIC_UDP_PORTS', '80,443,33494'),
        NTWA_TRUSTED_PROXIES=os.environ.get('NTWA_TRUSTED_PROXIES', ''),
    )
    if not enabled:
        return
    if len(os.environ.get('NTWA_SECRET_KEY', '')) < 32 or not config['NTWA_TRUSTED_HOSTS']:
        raise RuntimeError('Public mode requires NTWA_SECRET_KEY (at least 32 characters) and NTWA_TRUSTED_HOSTS')
    config['SESSION_COOKIE_SECURE'] = env_bool('NTWA_SESSION_COOKIE_SECURE', True)
    config['MAX_CONTENT_LENGTH'] = 8192
    config['NTWA_MAX_ACTIVE_TRACES'] = min(4, config['NTWA_MAX_ACTIVE_TRACES'])
    maximum = config['NTWA_TRACE_MAX_DURATION_SECONDS']
    config['NTWA_TRACE_MAX_DURATION_SECONDS'] = min(120, maximum) if maximum > 0 else 120
    config['NTWA_MIN_START_INTERVAL_SECONDS'] = max(2, config['NTWA_MIN_START_INTERVAL_SECONDS'])


def is_local_address(address):
    # UDP connect selects a route/source address without transmitting a probe.
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.connect((str(address), 9))
            return ipaddress.ip_address(connection.getsockname()[0]) == address
    except OSError:
        return False


class PublicPolicy:
    def __init__(self, config):
        self.config = config
        self.denied = networks(config.get('NTWA_PUBLIC_DENY_CIDRS', ''))
        self.proxies = networks(config.get('NTWA_TRUSTED_PROXIES', ''))
        self.device = config.get('NTWA_PUBLIC_DEVICE', '')
        self.ports = {}
        for protocol, default in [('tcp', '80,443'), ('udp', '80,443,33494')]:
            values = config.get('NTWA_PUBLIC_' + protocol.upper() + '_PORTS', default)
            ports = tuple(int(value) for value in values.split(','))
            if not ports or any(not 1 <= port <= 65535 for port in ports):
                raise ValueError('Invalid public port allowlist')
            self.ports[protocol] = ports
        # Transition mechanisms can route an apparently public IPv6 address to IPv4 internals.
        self.transition = networks('64:ff9b::/96,64:ff9b:1::/48,2002::/16,2001::/32')

    def client(self, request):
        peer = ipaddress.ip_address(request.remote_addr)
        trusted = peer.is_loopback or any(peer in network for network in self.proxies)
        address = peer
        if trusted and request.headers.get('X-Real-IP'):
            try:
                address = ipaddress.ip_address(request.headers['X-Real-IP'])
            except ValueError:
                raise PayloadError('invalid_payload', '客户端地址无效')
        address = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
        prefix = 32 if address.version == 4 else 64
        return str(ipaddress.ip_network((address, prefix), strict=False)), trusted

    def target(self, value):
        if not isinstance(value, str) or '%' in value:
            raise PayloadError('invalid_target', '目标地址无效')
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise PayloadError('invalid_target', '创建任务需要明确 IP')
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if (not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified
                or any(address in network for network in (*self.denied, *self.transition))
                or is_local_address(address)):
            raise PayloadError('target_not_allowed', '目标地址受限', status_code=403)
        return str(address)

    def resolve_target(self, target):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if '.' not in target or target.lower().endswith(('.localhost', '.local', '.internal', '.lan')):
                raise PayloadError('target_not_allowed', '目标地址受限', status_code=403)
        else:
            self.target(target)

    def prepare(self, target, extra):
        extra = dict(extra)
        version = extra.get('ipVersion')
        if version not in (None, '', 'all', 'ipv4', 'ipv6'):
            raise PayloadError('invalid_payload', '地址版本无效')
        if version in ('ipv4', 'ipv6') and ipaddress.ip_address(target).version != int(version[-1]):
            raise PayloadError('invalid_payload', '地址版本不符')
        interval = parse_positive_float(extra.get('intervalSeconds'), 'intervalSeconds', 1, 60)
        hop = parse_positive_int(extra.get('maxHop'), 'maxHop', 1, 30)
        first = parse_positive_int(extra.get('minHop'), 'minHop', 1, hop or 30)
        size = parse_positive_int(extra.get('packetSize'), 'packetSize', 0, 512)
        extra.update(intervalSeconds=interval or 1, maxHop=hop or 30, minHop=first or 1, packetSize=52 if size is None else size)
        if extra.get('device') not in (None, '', self.device):
            raise PayloadError('invalid_payload', '网卡受限')
        extra['device'] = self.device
        protocol = extra.get('protocol')
        if protocol not in (None, '', 'icmp', 'tcp', 'udp'):
            raise PayloadError('invalid_payload', '协议无效')
        if protocol in self.ports:
            port = parse_positive_int(extra.get('port'), 'port', 1, 65535)
            if port is not None and port not in self.ports[protocol]:
                raise PayloadError('invalid_payload', '端口受限')
            extra['port'] = self.ports[protocol][0] if port is None else port
        else:
            # The existing page always sends its port field; ICMP does not use it.
            parse_positive_int(extra.get('port'), 'port', 1, 65535)
            extra.pop('port', None)
        return build_trace_params(target, extra)

    def admit(self, registry, owner, client, params, active):
        if not client:
            raise PayloadError('invalid_payload', '缺少客户端地址')
        if any(task.owner == owner or task.client == client for task in active):
            raise PayloadError('trace_capacity_exceeded', '已有运行任务', 2)
        target = params[0]
        if sum(task.params[0] == target for task in active) >= 2:
            raise PayloadError('trace_capacity_exceeded', '目标任务已满', 2)
        # TTLs advance independently. Budget the sum of per-TTL rates, not one global interval.
        rate = (int(params[params.index('--max-hops') + 1]) - int(params[params.index('--first') + 1]) + 1) * 1000 / int(params[params.index('--ttl-time') + 1])
        if rate + sum(task.probe_rate for task in active) > 120:
            raise PayloadError('trace_capacity_exceeded', '探测配额已满', 2)
        registry.limits.rates([(('start', client), .1, 2), (('target', target), .1, 2), (('start', 'global'), 1, 4)])
        logging.info('public_trace_admitted active=%s reserved_pps=%.1f', len(active) + 1, rate)
        return rate
