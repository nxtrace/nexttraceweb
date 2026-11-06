import os
import ipaddress
import json
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
from nexttrace_mtr import INVALID_PARAM_PATTERN

DEVICE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,126}$"
HOSTNAME_PATTERN = r"^(?=.{1,255}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*$"
DATA_PROVIDER_ALLOWLIST = {
    "Ip2region",
    "ip2region",
    "IP.SB",
    "ip.sb",
    "IPInfo",
    "ipinfo",
    "IPInsight",
    "ipinsight",
    "IPAPI.com",
    "ip-api.com",
    "IPInfoLocal",
    "ipinfolocal",
    "chunzhen",
    "LeoMoeAPI",
    "leomoeapi",
    "disable-geoip",
}

def env_float(name: str, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        return float(raw_value)
    except ValueError:
        logging.warning("Invalid float in %s=%r, falling back to %s", name, raw_value, default)
        return default


def env_int(name: str, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        return int(raw_value)
    except ValueError:
        logging.warning("Invalid integer in %s=%r, falling back to %s", name, raw_value, default)
        return default


def env_bool(name: str, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None or raw_value == "":
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def parse_trusted_hosts(raw_value: Optional[str]) -> Tuple[str, ...]:
    if not raw_value:
        return ()
    hosts = []
    for host in raw_value.split(","):
        normalized = host.strip().lower()
        if normalized:
            hosts.append(normalized)
    return tuple(dict.fromkeys(hosts))


def load_secret_key() -> str:
    configured = os.environ.get("NTWA_SECRET_KEY")
    if configured:
        return configured
    generated = secrets.token_hex(32)
    logging.warning("NTWA_SECRET_KEY is unset; generated an ephemeral secret key for this process")
    return generated



@dataclass(frozen=True)
class PayloadError(Exception):
    code: str
    message: str
    retry_after_seconds: Optional[float] = None



def parse_json_object(raw_data: Any, field_name: str) -> Dict[str, Any]:
    if raw_data is None or raw_data == "":
        return {}
    if isinstance(raw_data, dict):
        return raw_data
    if isinstance(raw_data, str):
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise PayloadError("invalid_payload", f"{field_name} 不是合法的 JSON") from exc
        if isinstance(parsed, dict):
            return parsed
    raise PayloadError("invalid_payload", f"{field_name} 必须是对象")


def normalize_target(raw_target: Any) -> str:
    if raw_target is None:
        raise PayloadError("invalid_target", "缺少目标地址")
    target = str(raw_target).strip()
    if not target:
        raise PayloadError("invalid_target", "缺少目标地址")

    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or ""
    elif target.startswith("[") and "]" in target:
        target = target[1 : target.index("]")]
    elif target.count(":") == 1:
        host_part, port_part = target.rsplit(":", 1)
        if port_part.isdigit():
            target = host_part

    if INVALID_PARAM_PATTERN.search(target):
        raise PayloadError("invalid_target", "目标地址包含非法字符")
    if len(target) > 255:
        raise PayloadError("invalid_target", "目标地址过长")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if not re.match(HOSTNAME_PATTERN, target):
        raise PayloadError("invalid_target", "目标地址格式不合法")
    return target


def parse_client_payload(data: Any) -> Tuple[str, Dict[str, Any]]:
    payload = parse_json_object(data, "payload")
    if "ip" not in payload:
        raise PayloadError("invalid_payload", "payload 缺少 ip 字段")
    target = normalize_target(payload.get("ip"))
    extra = parse_json_object(payload.get("extra"), "extra")
    return target, extra


def parse_positive_int(value: Any, name: str, minimum: int, maximum: int) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PayloadError("invalid_payload", f"{name} 不是合法整数") from exc
    if not minimum <= parsed <= maximum:
        raise PayloadError("invalid_payload", f"{name} 超出允许范围")
    return parsed


def parse_positive_float(value: Any, name: str, minimum: float, maximum: float) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise PayloadError("invalid_payload", f"{name} 不是合法数字") from exc
    if not minimum <= parsed <= maximum:
        raise PayloadError("invalid_payload", f"{name} 超出允许范围")
    return parsed


def build_trace_params(target: str, extra: Dict[str, Any]) -> list:
    params = [target]

    ip_version = extra.get("ipVersion")
    if ip_version == "ipv4":
        params.append("--ipv4")
    elif ip_version == "ipv6":
        params.append("--ipv6")

    protocol = extra.get("protocol")
    if protocol == "tcp":
        params.append("--tcp")
    elif protocol == "udp":
        params.append("--udp")

    language = extra.get("language")
    if language == "en":
        params.extend(["--language", "en"])

    interval_seconds = parse_positive_float(extra.get("intervalSeconds"), "intervalSeconds", 0.005, 60.0)
    if interval_seconds is not None:
        params.extend(["--ttl-time", str(int(interval_seconds * 1000))])

    packet_size = parse_positive_int(extra.get("packetSize"), "packetSize", 0, 1500)
    if packet_size is not None:
        params.extend(["--psize", str(packet_size)])

    max_hop = parse_positive_int(extra.get("maxHop"), "maxHop", 1, 255)
    if max_hop is not None:
        params.extend(["--max-hops", str(max_hop)])

    min_hop = parse_positive_int(extra.get("minHop"), "minHop", 1, 255)
    if min_hop is not None:
        params.extend(["--first", str(min_hop)])

    port = parse_positive_int(extra.get("port"), "port", 1, 65535)
    if port is not None:
        params.extend(["--port", str(port)])

    device = extra.get("device")
    if device not in (None, ""):
        device = str(device).strip()
        if len(device) > 127 or not re.match(DEVICE_PATTERN, device):
            raise PayloadError("invalid_payload", "device 不合法")
        params.extend(["--dev", device])

    data_provider = extra.get("dataProvider")
    if data_provider not in (None, ""):
        data_provider = str(data_provider).strip()
        if data_provider not in DATA_PROVIDER_ALLOWLIST:
            raise PayloadError("invalid_payload", "dataProvider 不合法")
        params.extend(["--data-provider", data_provider])

    return params
