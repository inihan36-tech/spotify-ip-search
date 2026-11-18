#!/usr/bin/env python3
"""Поиск IPv4 для Spotify. Python 3.9+ и curl. Запуск: py -3 find_spotify_ip.py"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
from dataclasses import dataclass
from html import unescape
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
from tempfile import NamedTemporaryFile
from urllib.parse import urljoin, urlsplit


VERSION = "1.0.0"  # Обновляется вместе с тегом релиза.
LATEST_RELEASE_API = "https://api.github.com/repos/inihan36-tech/spotify-ip-search/releases/latest"
LATEST_RELEASE_URL = "https://github.com/inihan36-tech/spotify-ip-search/releases/latest"
METADATA_PATH = "/metadata/4/track/3n3Ppam7vgaVa1iaRUc9Lp"
TARGETS = {
    "spotify.com": "/",
    "www.spotify.com": "/",
    "api.spotify.com": "/v1/me",
    "login5.spotify.com": "/",
    "encore.scdn.co": "/",
    "gew1-spclient.spotify.com": METADATA_PATH,
    "spclient.wg.spotify.com": METADATA_PATH,
    "api-partner.spotify.com": "/pathfinder/v1/query",
    "aet.spotify.com": "/",
    "accounts.spotify.com": "/login",
    "open.spotify.com": "/",
    "accounts.scdn.co": "/",
    "gew1-dealer.spotify.com": "/",
    "www-growth.scdn.co": "/",
    "scdn.co": "/",
    "www.scdn.co": "/",
    "i.scdn.co": "/image/ab67616d00001e02ff9ca10b55ce82ae553c8228",
}
CORE_DOMAINS = ("open.spotify.com", "accounts.spotify.com", "api.spotify.com", "spclient.wg.spotify.com")
DISCOVERY_DOMAINS = (*CORE_DOMAINS, "i.scdn.co")
CDN_ROOTS = {"encore.scdn.co", "accounts.scdn.co", "www-growth.scdn.co", "scdn.co", "www.scdn.co"}
SYSTEM_DNS = "Системный DNS"
LOCAL = "Локальное разрешение"
SMART_DNS = "SmartDNS dns.malw.link"
SMART_DNS_SERVERS = ("179.254.166.171", "164.5.224.81")
DOH_RESOLVERS = {
    "Google Public DNS": ("https://dns.google/resolve", "8.8.8.8"),
    "Cloudflare DNS": ("https://cloudflare-dns.com/dns-query", "1.1.1.1"),
}
GEOHIDE_HOSTS = "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/main/hosts/"
ZAPRET_HOSTS = "https://raw.githubusercontent.com/StressOzz/Zapret-Manager/main/files/"
HOST_LISTS = {
    "GeoHide EU": GEOHIDE_HOSTS + "eu/hosts",
    "GeoHide RU": GEOHIDE_HOSTS + "hosts",
    "GeoHide US": GEOHIDE_HOSTS + "us/hosts",
    "dns.malw.link hosts": "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts",
    "Zapret-Manager EU": ZAPRET_HOSTS + "GeoHide_hosts_EU",
    "Zapret-Manager RU": ZAPRET_HOSTS + "GeoHide_hosts_RU",
    "Zapret-Manager US": ZAPRET_HOSTS + "GeoHide_hosts_US",
    "Zapret-Manager Malw": ZAPRET_HOSTS + "hosts_malw.link.txt",
}
DISCUSSION_BASE = "https://github.com/Flowseal/zapret-discord-youtube/discussions/"
DISCUSSIONS = {"GitHub #5552": DISCUSSION_BASE + "5552", "GitHub #12444": DISCUSSION_BASE + "12444"}
# Кандидаты из открытых списков и обсуждений на 18.11.2026. Проверяются при каждом запуске.
PUBLISHED_CANDIDATES = (
    "48.102.233.174", "217.60.179.6", "31.58.216.201", "37.221.93.128",
    "37.221.93.141", "5.175.161.3", "5.175.161.40", "45.13.237.213",
    "143.20.64.192", "31.25.239.132", "193.233.112.67", "159.194.200.33",
    "193.233.112.68", "193.233.112.88", "192.255.159.240", "192.255.159.241",
    "107.175.76.134", "192.3.233.253", "143.20.64.55", "217.60.245.219",
    "217.60.245.233", "2.27.118.34", "103.27.157.38", "45.155.204.190",
    "37.230.192.51", "77.239.114.0", "95.182.120.241", "204.12.192.222",
    "134.0.118.88", "185.246.223.127", "185.87.51.182", "142.54.189.109",
    "63.141.252.206", "46.8.158.6",
)
MAX_SOURCE_IPS = 32
WORKERS = 10
MIN_APPLY_DOMAINS = 9
METADATA_MARKER = b"\n__SPOTIFY_IP_RESULT__\n"


def public_ipv4(value):
    try:
        address = IPv4Address(value)
    except ValueError:
        return None
    if address.is_global and not address.is_multicast:
        return str(address)
    return None


def curl_request(curl, url, timeout, *, ip=None, metadata=False, interface=None,
                 limit=4_000_000, accept=None):
    args = [curl, "-q", "--silent", "--show-error", "--noproxy", "*",
            "--ipv4", "--proto", "=https", "--connect-timeout", str(min(timeout, 4)),
            "--max-time", str(timeout), "--max-filesize", str(limit)]
    if ip:
        args += ["--resolve", f"{urlsplit(url).hostname}:443:{ip}"]
    if interface:
        args += ["--interface", interface]
    if accept:
        args += ["--header", f"Accept: {accept}"]
    if metadata:
        args += ["--write-out", METADATA_MARKER.decode() +
                 "%{http_code}\n%{redirect_url}\n%{time_starttransfer}\n%{remote_ip}\n"
                 "%{content_type}\n%header{www-authenticate}"]
    else:
        args += ["--fail"]
    try:
        response = subprocess.run(args + [url], capture_output=True, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return 28, b""
    return response.returncode, response.stdout


def skip_dns_name(message, offset):
    while message[offset]:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length > 63:
            raise ValueError("invalid DNS label")
        offset += 1 + length
    return offset + 1


def smart_dns_lookup(domain, interface, context):
    query_id = 0x5350
    question = b"".join(bytes((len(label),)) + label.encode("ascii") for label in domain.split("."))
    query = struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0) + question + b"\x00\x00\x01\x00\x01"
    source_address = (interface, 0) if interface else None
    for server in SMART_DNS_SERVERS:
        try:
            with socket.create_connection((server, 853), timeout=4, source_address=source_address) as raw:
                with context.wrap_socket(raw, server_hostname="dns.malw.link") as tls:
                    tls.sendall(struct.pack("!H", len(query)) + query)
                    with tls.makefile("rb") as stream:
                        size, = struct.unpack("!H", stream.read(2))
                        reply = stream.read(size)
            response_id, flags, questions, answers, _, _ = struct.unpack_from("!6H", reply)
            if response_id != query_id or not flags & 0x8000 or flags & 0x020F or questions != 1:
                continue
            offset = skip_dns_name(reply, 12) + 4
            records = set()
            for _ in range(answers):
                offset = skip_dns_name(reply, offset)
                kind, record_class, _, length = struct.unpack_from("!HHIH", reply, offset)
                offset += 10
                data = reply[offset:offset + length]
                if kind == 1 and record_class == 1 and len(data) == length == 4:
                    address = public_ipv4(IPv4Address(data))
                    if address:
                        records.add(address)
                offset += length
            if records:
                return records, ""
        except (OSError, struct.error, IndexError, ValueError):
            continue
    return set(), "нет ответа DNS over TLS"


def doh_lookup(curl, domain, source, interface):
    endpoint, ip = DOH_RESOLVERS[source]
    error, body = curl_request(curl, f"{endpoint}?name={domain}&type=A", 4,
                               ip=ip, interface=interface, limit=64_000,
                               accept="application/dns-json")
    if error:
        return set(), f"curl {error}"
    try:
        reply = json.loads(body)
        if reply["Status"] != 0:
            return set(), f"DNS status {reply['Status']}"
        addresses = {ip for record in reply.get("Answer", []) if record["type"] == 1
                     and (ip := public_ipv4(record["data"]))}
    except (ValueError, KeyError, TypeError):
        return set(), "неожиданный ответ DNS"
    return addresses, ""


def lookup(powershell, curl, domain, source, interface, context):
    if source == SMART_DNS:
        return smart_dns_lookup(domain, interface, context)
    if source in DOH_RESOLVERS:
        return doh_lookup(curl, domain, source, interface)
    if source == LOCAL:
        try:
            records = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            return set(), str(exc)
        addresses = [record[4][0] for record in records]
    else:
        command = (f"Resolve-DnsName -Name '{domain}' -Type A -DnsOnly -NoHostsFile "
                   "-QuickTimeout -ErrorAction Stop")
        command += " | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue"
        try:
            result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                                    capture_output=True, timeout=7)
        except subprocess.TimeoutExpired:
            return set(), "тайм-аут DNS"
        if result.returncode:
            return set(), "ошибка DNS"
        addresses = result.stdout.decode("ascii", errors="replace").split()
    return {ip for value in addresses if (ip := public_ipv4(value))}, ""


def discussion_ips(page):
    # Извлекаем только соседние пары «IPv4 домен Spotify» из текста страницы.
    page = re.sub(r"<(script|style)\b[^>]*>.*?</\1\s*>", " ", page, flags=re.I | re.S)
    page = unescape(re.sub(r"<[^>]+>", " ", page))
    pattern = (r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})\s+"
               r"(?:[a-z0-9-]+\.)*(?:spotify\.com|spotifycdn\.(?:com|net)|scdn\.co)\b(?!\.)")
    matches = reversed(re.findall(pattern, page, flags=re.I))
    return list(dict.fromkeys(ip for value in matches if (ip := public_ipv4(value))))[:MAX_SOURCE_IPS]


def listed_hosts_ips(page):
    addresses = {}
    for line in page.splitlines():
        fields = line.partition("#")[0].split()
        if len(fields) < 2:
            continue
        ip = public_ipv4(fields[0])
        domains = {name.rstrip(".").lower() for name in fields[1:]} & TARGETS.keys()
        if ip and domains:
            addresses.setdefault(ip, set()).update(domains)
    return sorted(addresses, key=lambda ip: -len(addresses[ip]))[:MAX_SOURCE_IPS]


@dataclass(frozen=True)
class Probe:
    domain: str
    ip: str
    usable: bool
    reason: str
    seconds: float = 0.0


def expected_spotify_response(domain, code, content_type, authenticate, body, redirect=""):
    if domain == "api.spotify.com":
        if code != 401:
            return False
        try:
            error = json.loads(body)["error"]
            return error["status"] == 401 and "access token" in error["message"].lower()
        except (ValueError, KeyError, TypeError, AttributeError):
            return False

    if domain in ("spclient.wg.spotify.com", "gew1-spclient.spotify.com", "api-partner.spotify.com"):
        return code == 401 and 'realm="spotify"' in authenticate.lower()
    if domain == "i.scdn.co":
        return code == 200 and content_type.lower().startswith("image/") and bool(body)
    if domain in ("login5.spotify.com", "aet.spotify.com"):
        return code == 404 and not body.strip()
    if domain == "gew1-dealer.spotify.com":
        return code == 401 and body.strip() == b"401 Unauthorized"
    body = body.lower()
    if domain in CDN_ROOTS:
        return (code == 200 and bool(body)) or (code == 403 and (b"access denied" in body or b"forbidden" in body))
    if domain in ("spotify.com", "www.spotify.com") and code in (301, 302, 303, 307, 308):
        expected = "www.spotify.com" if domain == "spotify.com" else "open.spotify.com"
        destination = urlsplit(redirect)
        return destination.scheme == "https" and destination.netloc.lower() == expected
    return code == 200 and b"<html" in body and b"spotify" in body


def probe(curl, domain, ip, timeout, interface=None, *, retry_timeout=False):
    url = f"https://{domain}{TARGETS[domain]}"
    seconds = 0.0
    for _ in range(3):
        error, data = curl_request(curl, url, timeout, ip=ip, metadata=True, interface=interface)
        if error == 28 and retry_timeout:
            retry_timeout = False
            error, data = curl_request(curl, url, timeout, ip=ip, metadata=True, interface=interface)
        if error:
            return Probe(domain, ip, False, f"curl {error}")
        body, _, metadata = data.rpartition(METADATA_MARKER)
        try:
            code_text, redirect, elapsed, remote_ip, content_type, auth = (
                metadata.decode("utf-8", errors="replace").split("\n", 5))
            code = int(code_text)
            seconds += float(elapsed)
            if remote_ip != ip:
                return Probe(domain, ip, False, "соединение ушло на другой IP")
            if code in (301, 302, 303, 307, 308) and redirect:
                next_url = urljoin(url, redirect)
                destination = urlsplit(next_url)
                if destination.scheme == "https" and destination.netloc.lower() == domain:
                    url = next_url
                    continue
            usable = expected_spotify_response(domain, code, content_type, auth, body, redirect)
        except ValueError:
            return Probe(domain, ip, False, "неожиданный ответ")
        return Probe(domain, ip, usable, f"HTTP {code}", seconds)
    return Probe(domain, ip, False, "слишком много перенаправлений")


def physical_addresses(powershell):
    command = ("Get-NetAdapter -Physical | Where-Object Status -eq Up | "
               "Get-NetIPConfiguration | Where-Object IPv4DefaultGateway | "
               "ForEach-Object { $_.IPv4Address.IPAddress }")
    try:
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, timeout=7)
    except subprocess.TimeoutExpired:
        return []
    return result.stdout.decode("ascii", errors="replace").split()


def ip_is_overridden(curl, interface=None):
    # Публичный DNS Cloudflare не обслуживает HTTPS Spotify.
    return probe(curl, "open.spotify.com", "1.1.1.1", 3, interface).usable


def check_candidates(pool, curl, candidates, timeout, verbose, interface):
    futures = [pool.submit(probe, curl, domain, ip, timeout, interface, retry_timeout=True)
               for ip, domains in candidates.items() for domain in TARGETS if domain in domains]
    results = [future.result() for future in futures]
    if verbose:
        for item in results:
            status = "OK" if item.usable else "FAIL"
            print(f"  {status:4} {item.ip:15} {item.domain:22} {item.reason}")
    return results


def scan_candidates(pool, curl, candidates, results, timeout, verbose, interface):
    tested = {(item.ip, item.domain) for item in results}
    core_pairs = {ip: {domain for domain in CORE_DOMAINS if domain in domains and (ip, domain) not in tested}
                  for ip, domains in candidates.items()}
    results.extend(check_candidates(pool, curl, core_pairs, timeout, verbose, interface))
    responsive_ips = {item.ip for item in results if item.usable and item.domain in CORE_DOMAINS}
    remaining = {ip: {domain for domain in TARGETS if domain not in CORE_DOMAINS and (ip, domain) not in tested}
                 for ip in candidates if ip in responsive_ips}
    if any(remaining.values()):
        if verbose:
            print("  Проверяю остальные домены на ответивших IP…", flush=True)
        results.extend(check_candidates(pool, curl, remaining, timeout, verbose, interface))


def best_ip(results):
    passed = {}
    for result in results:
        if result.usable:
            passed.setdefault(result.ip, {})[result.domain] = result.seconds
    ip = min(passed, key=lambda ip: (-len(passed[ip]), sum(passed[ip].values()), ip), default=None)
    return ip, len(passed[ip]) if ip else 0


def confirm_winner(pool, curl, results, timeout, verbose, interface):
    candidates = {(item.domain, item.ip): item for item in results}
    while True:
        best, coverage = best_ip(candidates.values())
        if coverage < len(TARGETS):
            return list(candidates.values())
        print(f"Контрольная проверка {best} на {len(TARGETS)} доменах…", flush=True)
        checks = [pool.submit(probe, curl, domain, best, timeout, interface) for domain in TARGETS]
        failures = [result for future in checks if not (result := future.result()).usable]
        if not failures:
            # Оставляем порядок, в котором адрес выиграл первый раунд.
            return list(candidates.values())
        for result in failures:
            candidates[result.domain, result.ip] = result
            if verbose:
                print(f"  Нестабильно: {result.ip} {result.domain} ({result.reason})")


def update_hosts_contents(original, ip, domains):
    if b"\x00" in original:
        raise ValueError("Файл hosts содержит нулевые байты. Проверьте его кодировку.")
    bom = b"\xef\xbb\xbf" if original.startswith(b"\xef\xbb\xbf") else b""
    content = original[len(bom):]
    newline = b"\r\n" if b"\r\n" in content or b"\n" not in content else b"\n"
    names = {domain.encode("ascii") for domain in domains}
    lines = []
    for line in content.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        fields, separator, comment = body.partition(b"#")
        columns = fields.split()
        aliases = columns[1:]
        kept = [alias for alias in aliases if alias.lower().rstrip(b".") not in names]
        if len(kept) == len(aliases):
            lines.append(line)
        elif kept:
            suffix = b" " + separator + comment if separator else b""
            lines.append(b" ".join([columns[0], *kept]) + suffix + newline)
        elif separator:
            lines.append(separator + comment + newline)
    content = b"".join(lines)
    if content and not content.endswith(b"\n"):
        content += newline
    records = (f"{ip} {domain}".encode("ascii") + newline for domain in domains)
    return bom + content + b"".join(records)


def write_hosts(path, ip, domains):
    original = path.read_bytes()
    updated = update_hosts_contents(original, ip, domains)
    if updated == original:
        return
    stream = NamedTemporaryFile(dir=path.parent, prefix="hosts.", suffix=".tmp", delete=False)
    temporary = Path(stream.name)
    try:
        with stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != original:
            raise OSError("Файл hosts изменился во время записи. Запустите скрипт ещё раз.")
        replace = ctypes.WinDLL("kernel32", use_last_error=True).ReplaceFileW
        replace.argtypes = [ctypes.c_wchar_p] * 3 + [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
        if not replace(str(path), str(temporary), None, 0, None, None):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        temporary.unlink(missing_ok=True)


def clear_spotify_web_cache():
    local = Path(os.environ["LOCALAPPDATA"])
    roots = [local / "Spotify", Path(os.environ["APPDATA"]) / "Spotify"]
    roots.extend(package / "LocalCache" / "Spotify"
                 for package in (local / "Packages").glob("SpotifyAB.SpotifyMusic_*"))
    removed = 0
    failed = False
    for root in roots:
        browser = root / "Browser"
        profiles = [browser, browser / "Default", root / "Default", root / "User Data" / "Default"]
        profiles.extend(browser.glob("Profile *"))
        for profile in profiles:
            for name in ("Cache", "Code Cache", "GPUCache"):
                path = profile / name
                try:
                    if path.is_dir() and path.resolve() == path.absolute():
                        shutil.rmtree(path)
                        removed += 1
                except OSError as exc:
                    print(f"Ошибка очистки {path}: {exc}")
                    failed = True
    print(f"Веб-кэш   · очищено папок: {removed}")
    if failed:
        print("Закройте Spotify и повторите запуск, чтобы удалить занятые файлы.")
    return not failed


def apply_result(ip, domains):
    system = Path(os.environ["SystemRoot"]) / "System32"
    try:
        write_hosts(system / "drivers" / "etc" / "hosts", ip, domains)
    except (OSError, ValueError) as exc:
        print(f"hosts     · ошибка записи: {exc}")
        return 2
    print(f"hosts     · записано доменов: {len(domains)}")
    cache_ok = clear_spotify_web_cache()
    try:
        result = subprocess.run([str(system / "ipconfig.exe"), "/flushdns"],
                                capture_output=True, timeout=15)
        dns_ok = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        dns_ok = False
    print("DNS       · кэш сброшен" if dns_ok else "DNS       · ошибка сброса кэша")
    print("\nПерезапустите Spotify, если он открыт.")
    return 0 if cache_ok and dns_ok else 2


def print_results(results, sources, apply=False, verbose=False):
    best, coverage = best_ip(results)
    count = len({item.ip for item in results})
    print(f"\nРезультат · проверено IP: {count}")
    if best is None:
        print("Подходящий IP не найден.")
        return 1
    print(f"Лучший IP · {best} · {coverage}/{len(TARGETS)} доменов")
    passed = {item.domain for item in results if item.ip == best and item.usable}
    essential = [domain for domain in ("open.spotify.com", "accounts.spotify.com") if domain not in passed]
    if essential:
        print(f"Доступ не подтверждён: {', '.join(essential)}")
    if verbose:
        print(f"Источники: {', '.join(sources[best])}")
        omitted = [domain for domain in TARGETS if domain not in passed]
        if omitted:
            print(f"Все домены без подтверждения: {', '.join(omitted)}")
        print("Проверен HTTPS. Вход в аккаунт и воспроизведение не проверялись.")
    if apply and coverage >= MIN_APPLY_DOMAINS:
        print()
        return apply_result(best, [domain for domain in TARGETS if domain in passed])
    if apply:
        print(f"hosts     · запись пропущена, нужны хотя бы {MIN_APPLY_DOMAINS}/{len(TARGETS)} доменов")
    print("\nСтроки для hosts\n")
    for domain in TARGETS:
        if domain in passed:
            print(f"{best} {domain}")
    return 0 if coverage == len(TARGETS) else 1


def host_list(curl, label, url, parse):
    error, body = curl_request(curl, url, 10, limit=8_000_000)
    if error == 28:
        error, body = curl_request(curl, url, 10, limit=8_000_000)
    if error:
        return label, [], f"curl {error}"
    return label, parse(body.decode("utf-8-sig", errors="replace")), ""


def fallback_sources(pool, curl):
    yield [("Встроенный список", PUBLISHED_CANDIDATES, "")]
    for sources, parse in ((HOST_LISTS, listed_hosts_ips), (DISCUSSIONS, discussion_ips)):
        tasks = [pool.submit(host_list, curl, label, url, parse) for label, url in sources.items()]
        yield [task.result() for task in tasks]


def check_for_update(curl):
    error, body = curl_request(curl, LATEST_RELEASE_API, 3, limit=256_000,
                               accept="application/vnd.github+json")
    if error:
        return
    try:
        tag = json.loads(body)["tag_name"]
        match = re.fullmatch(r"v?(\d{1,9}\.\d{1,9}\.\d{1,9})", tag)
    except (ValueError, KeyError, TypeError):
        return
    if match is None:
        return
    latest = match.group(1)
    if tuple(map(int, latest.split("."))) > tuple(map(int, VERSION.split("."))):
        print(f"\nДоступно обновление v{latest} · {LATEST_RELEASE_URL}")


def finish_search(curl, results, sources, apply, verbose):
    status = print_results(results, sources, apply, verbose)
    check_for_update(curl)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--dns-only", action="store_true", help="пропустить все списки адресов и обсуждения на GitHub")
    parser.add_argument("--exclude", metavar="IP", action="append", default=[],
                        help="пропустить старый IPv4 (можно указать несколько раз)")
    parser.add_argument("--check-ip", metavar="IP", help="проверить один IPv4 на всех доменах Spotify")
    parser.add_argument("--apply", action="store_true", help="обновить hosts и очистить веб-кэш Spotify и DNS")
    parser.add_argument("--verbose", action="store_true", help="показать результат каждого запроса")
    parser.add_argument("--timeout", type=int, choices=range(2, 16), metavar="2–15", default=5,
                        help="лимит на одну HTTPS-проверку в секундах (по умолчанию 5)")
    args = parser.parse_args()
    if args.apply and (os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin()):
        parser.exit(2, "Для записи hosts запустите CMD или PowerShell от имени администратора.\n")
    curl = shutil.which("curl.exe") or shutil.which("curl")
    powershell = shutil.which("powershell.exe")
    if not curl or not powershell:
        parser.exit(2, "Для запуска нужны curl.exe и Windows PowerShell.\n")
    excluded = {public_ipv4(ip) for ip in args.exclude}
    if None in excluded:
        parser.error("--exclude ожидает публичный IPv4")
    selected_ip = public_ipv4(args.check_ip) if args.check_ip is not None else None
    if args.check_ip is not None and (selected_ip is None or selected_ip in excluded):
        parser.error("--check-ip ожидает публичный IPv4, которого нет в --exclude")

    print("Spotify · поиск IP\n", flush=True)
    interface = None
    if ip_is_overridden(curl):
        if args.verbose:
            print("Туннель перенаправляет HTTPS. Ищу физический адаптер…", flush=True)
        interface = next((address for address in physical_addresses(powershell)
                          if not ip_is_overridden(curl, address)), None)
        if not interface:
            print("Проверить конкретные IP не удалось. Отключите режим TUN и повторите запуск.")
            return 2
        print("Маршрут   · прямое подключение", flush=True)

    if selected_ip:
        print(f"Проверка  · {selected_ip} на {len(TARGETS)} доменах…", flush=True)
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = check_candidates(pool, curl, {selected_ip: TARGETS}, args.timeout, args.verbose, interface)
            results = confirm_winner(pool, curl, results, args.timeout, args.verbose, interface)
        return finish_search(curl, results, {selected_ip: ("IP указан вручную",)}, args.apply, args.verbose)

    sources = {}
    candidate_domains = {}
    context = ssl.create_default_context()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        print("Поиск     · DNS…", flush=True)
        queries = [(source, domain, pool.submit(lookup, powershell, curl, domain, source, interface, context))
                   for source in (SYSTEM_DNS, SMART_DNS, LOCAL, *DOH_RESOLVERS) for domain in DISCOVERY_DOMAINS]
        for source, domain, future in queries:
            addresses, error = future.result()
            if args.verbose:
                answer = error or ", ".join(sorted(addresses)) or "нет IPv4"
                print(f"  {source} · {domain}: {answer}")
            for ip in sorted(addresses - excluded):
                sources.setdefault(ip, {})[source] = None
                domains = (domain,) if source in DOH_RESOLVERS else TARGETS
                candidate_domains.setdefault(ip, set()).update(domains)

        print(f"Проверка  · адресов из DNS: {len(sources)}", flush=True)
        results = []
        scan_candidates(pool, curl, candidate_domains, results, args.timeout, args.verbose, interface)
        results = confirm_winner(pool, curl, results, args.timeout, args.verbose, interface)
        if not args.dns_only and best_ip(results)[1] < len(TARGETS):
            print(f"Проверка  · резервный список: {len(PUBLISHED_CANDIDATES)} IP", flush=True)
            unavailable = 0
            for index, lists in enumerate(fallback_sources(pool, curl)):
                candidates = {}
                for label, addresses, error in lists:
                    if error:
                        unavailable += 1
                    if args.verbose:
                        print(f"  {label} · {error or ', '.join(addresses) or 'нет IPv4'}", flush=True)
                    for ip in addresses:
                        if ip not in excluded:
                            sources.setdefault(ip, {})[label] = None
                            candidates[ip] = TARGETS
                scan_candidates(pool, curl, candidates, results, args.timeout, args.verbose, interface)
                results = confirm_winner(pool, curl, results, args.timeout, args.verbose, interface)
                if best_ip(results)[1] == len(TARGETS):
                    break
                if index == 0:
                    print("Поиск     · открытые списки…", flush=True)
            if unavailable:
                print(f"Источники · недоступно: {unavailable}", flush=True)

    return finish_search(curl, results, sources, args.apply, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
