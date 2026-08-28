#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import ftplib
import html
import ipaddress
import itertools
import json
import os
import pty
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple


SNMP_SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SNMP_SYS_CONTACT_OID = "1.3.6.1.2.1.1.4.0"


@dataclass
class SNMPResult:
    community: str
    readable: bool
    writable: Optional[bool]
    sys_descr: Optional[str]
    note: Optional[str]
    version: Optional[str] = None  # 讀取成功時實際使用的 SNMP 版本（1 或 2c）


@dataclass
class FTPResult:
    username: str
    password: str
    success: bool
    banner: Optional[str]
    note: Optional[str]
    file_list: Optional[List[str]] = None
    fail_kind: Optional[str] = None  # 失敗類型："auth"(帳密錯誤) / "conn"(連線問題) / "other"；成功為 None
    list_error: Optional[str] = None  # 登入成功但列根目錄失敗時的原因（None 表示成功或真的空目錄）


@dataclass
class HostResult:
    host: str
    ftp_open: bool
    snmp_open: bool
    ftp_results: List[FTPResult]
    snmp_results: List[SNMPResult]


def require_binary(name: str) -> None:
    if shutil.which(name) is None:
        print(f"[!] 找不到必要工具：{name}", file=sys.stderr)
        sys.exit(1)


def read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        print(f"[!] 找不到檔案：{path}", file=sys.stderr)
        sys.exit(1)

    items: List[str] = []

    # 用 utf-8-sig 讀取以自動去除檔首 BOM；否則第一行會被黏上 \ufeff，
    # 造成第一個 community / 帳密 / IP 對不上或格式錯誤（常見於 Windows 記事本存的檔）。
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            # 再逐行防禦性清掉任何殘留 BOM（例如多檔串接時可能出現在中間）
            item = line.replace("\ufeff", "").strip()

            if not item:
                continue

            if item.startswith("#"):
                continue

            items.append(item)

    return items


def is_ipv4_address(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def expand_full_ip_range_to_cidrs(start_ip: str, end_ip: str) -> List[str]:
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    if int(start) > int(end):
        raise ValueError(f"IP range 起始位址大於結束位址：{start_ip}-{end_ip}")

    networks = ipaddress.summarize_address_range(start, end)
    return [str(network) for network in networks]


def read_ip_ranges(path: str) -> List[str]:
    """
    支援格式：

    1. 單一 IP
       192.168.1.10

    2. CIDR
       192.168.1.0/24

    3. nmap 原生 range
       172.16.1.1-50
       192.168.0-10.1-254

    4. 完整 IP 起訖範圍
       192.168.0.0-192.168.10.255

       會自動轉成 CIDR 後交給 nmap。
    """
    raw_targets = read_lines(path)

    if not raw_targets:
        print(f"[!] {path} 沒有可用的掃描目標。", file=sys.stderr)
        sys.exit(1)

    expanded_targets: List[str] = []

    for item in raw_targets:
        item = item.strip()

        if "-" in item:
            left, right = item.split("-", 1)
            left = left.strip()
            right = right.strip()

            if is_ipv4_address(left) and is_ipv4_address(right):
                try:
                    cidrs = expand_full_ip_range_to_cidrs(left, right)
                    expanded_targets.extend(cidrs)

                    print(f"[*] IP range 已轉換：{item}")
                    for cidr in cidrs:
                        print(f"    -> {cidr}")

                    continue

                except ValueError as e:
                    print(f"[!] IP range 格式錯誤：{e}", file=sys.stderr)
                    sys.exit(1)

        expanded_targets.append(item)

    return expanded_targets


def read_snmp_communities(path: str) -> List[str]:
    communities = read_lines(path)

    if not communities:
        print(f"[!] {path} 沒有可用的 SNMP community string。", file=sys.stderr)
        sys.exit(1)

    return communities


def read_ftp_list(path: str) -> Tuple[List[str], List[str], List[Tuple[str, str]], str]:
    """
    支援兩種格式：

    1. 單字交叉模式：
       admin
       password
       123456

       會測試：
       admin:admin
       admin:password
       admin:123456
       password:admin
       ...

    2. 指定帳密模式：
       admin:admin
       admin:password
       root:root

       只測試指定 user:password。
    """
    items = read_lines(path)

    if not items:
        print(f"[!] {path} 沒有可用的 FTP 字典資料。", file=sys.stderr)
        sys.exit(1)

    pair_lines = [item for item in items if ":" in item]

    if pair_lines:
        pairs: List[Tuple[str, str]] = []

        for item in pair_lines:
            username, password = item.split(":", 1)
            username = username.strip()
            password = password.strip()

            if username and password:
                pairs.append((username, password))

        if not pairs:
            print(f"[!] {path} 使用指定帳密模式，但沒有有效的 user:password。", file=sys.stderr)
            sys.exit(1)

        return [], [], pairs, "pair"

    return items, items, [], "wordlist"


def run_command(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def run_nmap_streaming(cmd: List[str], timeout: int, stats_prefix: str) -> Tuple[int, str]:
    """
    以偽終端機（pty）執行 nmap。

    nmap 只有在偵測到 stdout 是真正的終端機時，才會即時印出 -v /
    --stats-every 的互動式進度訊息；一旦 stdout 被導向管線（例如一般的
    subprocess.PIPE），這些訊息會被整批緩衝到掃描結束才吐出，即使
    --stats-every 的間隔設得再短也一樣看不到即時進度。用 pty 讓 nmap
    誤判為連到終端機，才能真正即時看到掃描進度。
    """
    master_fd, slave_fd = pty.openpty()

    proc = subprocess.Popen(cmd, stdout=slave_fd, stderr=slave_fd, close_fds=True)
    os.close(slave_fd)

    output_lines: List[str] = []

    def _emit(raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace").rstrip("\r")
        if text:
            output_lines.append(text)
            print(f"    {stats_prefix} {text}")

    def _reader() -> None:
        buf = b""
        while True:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break

            if not chunk:
                break

            buf += chunk

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                _emit(line)

        if buf:
            _emit(buf)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    rc: int
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = 124
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    t.join(timeout=5)

    try:
        os.close(master_fd)
    except OSError:
        pass

    output = "\n".join(output_lines)

    if rc == 124:
        return 124, output or "timeout"

    return rc, output


def build_nmap_ports(mode: str) -> str:
    if mode == "all":
        return "T:21,U:161"

    if mode == "ftp":
        return "T:21"

    if mode == "snmp":
        return "U:161"

    raise ValueError(f"不支援的 mode：{mode}")


def build_nmap_scan_flags(mode: str) -> List[str]:
    """
    all  : TCP SYN + UDP
    ftp  : TCP SYN
    snmp : UDP
    """
    if mode == "all":
        return ["-sS", "-sU"]

    if mode == "ftp":
        return ["-sS"]

    if mode == "snmp":
        return ["-sU"]

    raise ValueError(f"不支援的 mode：{mode}")


def _parse_nmap_xml_hosts(stdout: str, chunk_label: str) -> Dict[str, Dict[str, bool]]:
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError as e:
        raise RuntimeError(f"nmap XML 解析失敗 {chunk_label}：{e}") from e

    discovered: Dict[str, Dict[str, bool]] = {}

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")

        if addr_elem is None:
            continue

        ip = addr_elem.attrib.get("addr")

        if not ip:
            continue

        ftp_open = False
        snmp_open = False
        snmp_filtered = False  # UDP/161 為 open|filtered（不確定，但仍值得用 snmpget 實測）

        ports_elem = host.find("ports")

        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                proto = port.attrib.get("protocol")
                portid = port.attrib.get("portid")

                state_elem = port.find("state")

                if state_elem is None:
                    continue

                state = state_elem.attrib.get("state")

                # TCP/21：TCP 有三向交握，狀態可信，只認 open。
                if proto == "tcp" and portid == "21":
                    if state == "open":
                        ftp_open = True

                # UDP/161：UDP 無交握，nmap 對未回應的 UDP 埠常標成 open|filtered。
                # 若在此只認嚴格 "open"，會漏掉大量真的有開 SNMP 的設備。
                # 因此 open 與 open|filtered 都視為候選，交給後續 snmpget 實測確認，
                # snmpget 才是 SNMP 是否真的可達的最終判準。
                if proto == "udp" and portid == "161":
                    if state == "open":
                        snmp_open = True
                    elif state == "open|filtered":
                        snmp_filtered = True

        if ftp_open or snmp_open or snmp_filtered:
            discovered[ip] = {
                "ftp": ftp_open,
                # open 或 open|filtered 都送進後續 SNMP 稽核流程
                "snmp": snmp_open or snmp_filtered,
                "snmp_filtered": snmp_filtered and not snmp_open,
            }

    return discovered


def split_targets(targets: List[str], n: int) -> List[List[str]]:
    """
    將目標清單以 round-robin 方式切成最多 n 份，讓大小不一的網段盡量平均分散到
    各個分片，而不是把清單前段（可能剛好都是大網段）集中到同一份。
    """
    n = max(1, min(n, len(targets))) if targets else 1
    chunks: List[List[str]] = [[] for _ in range(n)]

    for i, target in enumerate(targets):
        chunks[i % n].append(target)

    return [chunk for chunk in chunks if chunk]


def _nmap_scan_chunk(
    targets: List[str],
    mode: str,
    host_timeout: str,
    max_retries: int,
    pn: bool,
    stats_interval: str,
    min_rate: Optional[int],
    timing: str,
    chunk_label: str,
) -> Dict[str, Dict[str, bool]]:
    ports = build_nmap_ports(mode)
    scan_flags = build_nmap_scan_flags(mode)

    xml_fd, xml_path = tempfile.mkstemp(prefix="nmap_audit_", suffix=".xml")
    os.close(xml_fd)

    try:
        cmd = [
            "nmap",
            "-oX",
            xml_path,
            *scan_flags,
            f"-T{timing}",
            "--open",
            "-n",  # 稽核以 IP 為對象，關閉反向 DNS 解析，省下每台主機的 DNS 等待，明顯加速
            "-p",
            ports,
            "--max-retries",
            str(max_retries),
            "--host-timeout",
            host_timeout,
            "--stats-every",
            stats_interval,
            "-v",
        ]

        # UDP 掃描（all / snmp 模式）容易被目標的 ICMP port-unreachable 速率限制拖慢。
        # --defeat-icmp-ratelimit 讓 nmap 不再苦等被限速的 ICMP 回應，大幅加速 UDP 掃描；
        # 我們只在意「開啟」的埠，故對本工具的判定準確度沒有負面影響。
        if "-sU" in scan_flags:
            cmd.append("--defeat-icmp-ratelimit")

        if min_rate:
            cmd.extend(["--min-rate", str(min_rate)])

        if pn:
            cmd.append("-Pn")

        cmd.extend(targets)

        print(f"[*] 執行 nmap 掃描 {chunk_label}（{len(targets)} 個目標）")
        print(f"    {' '.join(cmd)}")

        rc, output = run_nmap_streaming(cmd, timeout=7200, stats_prefix=chunk_label)

        if rc != 0:
            msg = f"nmap 掃描失敗 {chunk_label}。請確認是否使用 sudo 執行，以及目標格式是否正確。"

            if output:
                msg += f"\n{output}"

            raise RuntimeError(msg)

        with open(xml_path, "r", encoding="utf-8") as f:
            xml_text = f.read()

    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass

    return _parse_nmap_xml_hosts(xml_text, chunk_label)


def nmap_scan_targets(
    targets: List[str],
    mode: str,
    host_timeout: str,
    max_retries: int,
    pn: bool,
    nmap_workers: int = 1,
    stats_interval: str = "10s",
    min_rate: Optional[int] = None,
    timing: str = "4",
) -> Dict[str, Dict[str, bool]]:
    print("[*] 執行 nmap 掃描")
    print(f"    模式：{mode}")

    target_chunks = split_targets(targets, nmap_workers)
    total_chunks = len(target_chunks)

    print(f"    目標總數：{len(targets)}，分成 {total_chunks} 個並行 nmap 分片（--nmap-workers={nmap_workers}）")

    discovered: Dict[str, Dict[str, bool]] = {}
    completed = 0
    completed_lock = threading.Lock()
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=total_chunks) as executor:
        future_to_label = {}

        for idx, chunk in enumerate(target_chunks, start=1):
            label = f"[nmap#{idx}/{total_chunks}]"
            future = executor.submit(
                _nmap_scan_chunk,
                chunk,
                mode,
                host_timeout,
                max_retries,
                pn,
                stats_interval,
                min_rate,
                timing,
                label,
            )
            future_to_label[future] = label

        for future in concurrent.futures.as_completed(future_to_label):
            label = future_to_label[future]

            try:
                chunk_result = future.result()
            except Exception as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)

            discovered.update(chunk_result)

            with completed_lock:
                completed += 1
                done = completed

            elapsed = time.time() - start_time
            print(
                f"[進度] nmap 分片 {done}/{total_chunks} 完成 {label}，"
                f"目前累積發現 {len(discovered)} 台主機，已耗時 {elapsed:.0f}s"
            )

    return discovered


def _snmp_get_one_version(
    host: str,
    community: str,
    oid: str,
    timeout_sec: int,
    retries: int,
    version: str,
) -> Tuple[bool, Optional[str], Optional[str]]:
    cmd = [
        "snmpget",
        f"-v{version}",
        "-c",
        community,
        "-t",
        str(timeout_sec),
        "-r",
        str(retries),
        "-Oqv",
        host,
        oid,
    ]

    # 逾時上限 = snmpget 自身逾時 x (重試次數+1) 再加緩衝，避免外層過早殺掉仍在重試的 snmpget
    outer_timeout = timeout_sec * (retries + 1) + 3
    rc, stdout, stderr = run_command(cmd, timeout=outer_timeout)

    if rc == 0 and stdout:
        value = stdout.strip()

        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        return True, value, None

    return False, None, stderr or stdout or "SNMP read failed"


def snmp_get(
    host: str,
    community: str,
    oid: str,
    timeout_sec: int,
    retries: int = 1,
    versions: Optional[List[str]] = None,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    依序嘗試多個 SNMP 版本（預設 2c 再 1），任一版本讀到就算成功。

    這解決兩個常見的漏報：
    1. 舊型印表機 / UPS / 工控與監控設備常常只支援 SNMPv1，原本只測 v2c 會整批漏掉。
    2. SNMP 走 UDP，封包可能單純掉包；retries>0 可大幅降低「其實可讀卻被判為不可讀」的偽陰性。

    回傳：(readable, value, note, version_used)
    """
    if versions is None:
        versions = ["2c", "1"]

    last_note: Optional[str] = None

    for version in versions:
        readable, value, note = _snmp_get_one_version(
            host=host,
            community=community,
            oid=oid,
            timeout_sec=timeout_sec,
            retries=retries,
            version=version,
        )

        if readable:
            return True, value, None, version

        last_note = note

    return False, None, last_note or "SNMP read failed", None


def snmp_set_same_value(
    host: str,
    community: str,
    oid: str,
    value: str,
    timeout_sec: int,
    retries: int = 1,
    version: str = "2c",
) -> Tuple[Optional[bool], Optional[str]]:
    """
    保守寫入測試：
    先讀 sysContact.0，再把相同值寫回 sysContact.0。

    注意：
    這仍然是 SNMP SET 操作。
    建議只在授權維護時段或測試環境啟用。

    version 應使用該 community 讀取成功時的版本，避免用錯版本造成偽陰性。
    """
    cmd = [
        "snmpset",
        f"-v{version}",
        "-c",
        community,
        "-t",
        str(timeout_sec),
        "-r",
        str(retries),
        host,
        oid,
        "s",
        value,
    ]

    outer_timeout = timeout_sec * (retries + 1) + 3
    rc, stdout, stderr = run_command(cmd, timeout=outer_timeout)

    if rc == 0:
        return True, None

    msg = stderr or stdout or "SNMP set failed"
    msg_lower = msg.lower()

    if "notwritable" in msg_lower:
        return False, msg

    if "not writable" in msg_lower:
        return False, msg

    if "authorizationerror" in msg_lower:
        return False, msg

    if "noaccess" in msg_lower:
        return False, msg

    if "timeout" in msg_lower:
        return None, msg

    return False, msg


def _audit_one_community(
    host: str,
    community: str,
    write_test: bool,
    timeout_sec: int,
    delay_sec: float,
    retries: int,
    versions: List[str],
    serial: bool,
) -> SNMPResult:
    # 串列模式（snmp_workers==1）才套用 delay，維持對敏感設備的溫和節奏；
    # 並行模式下已用執行緒數控制壓力，額外 sleep 只會拖慢整體。
    if serial and delay_sec > 0:
        time.sleep(delay_sec)

    readable, sys_descr, read_note, version_used = snmp_get(
        host=host,
        community=community,
        oid=SNMP_SYS_DESCR_OID,
        timeout_sec=timeout_sec,
        retries=retries,
        versions=versions,
    )

    if not readable:
        return SNMPResult(
            community=community,
            readable=False,
            writable=None,
            sys_descr=None,
            note=read_note,
            version=None,
        )

    writable: Optional[bool] = None
    note: Optional[str] = None

    if write_test:
        # 用讀取成功的版本進行後續讀 / 寫，避免版本不一致造成偽陰性
        set_version = version_used or "2c"

        contact_ok, contact_value, contact_note, _ = snmp_get(
            host=host,
            community=community,
            oid=SNMP_SYS_CONTACT_OID,
            timeout_sec=timeout_sec,
            retries=retries,
            versions=[set_version],
        )

        if contact_ok and contact_value is not None:
            writable, note = snmp_set_same_value(
                host=host,
                community=community,
                oid=SNMP_SYS_CONTACT_OID,
                value=contact_value,
                timeout_sec=timeout_sec,
                retries=retries,
                version=set_version,
            )
        else:
            writable = None
            note = f"可讀，但無法讀取 sysContact.0 進行保守寫入測試：{contact_note}"

    return SNMPResult(
        community=community,
        readable=True,
        writable=writable,
        sys_descr=sys_descr,
        note=note,
        version=version_used,
    )


def audit_snmp_host(
    host: str,
    communities: List[str],
    write_test: bool,
    timeout_sec: int,
    delay_sec: float,
    retries: int = 1,
    versions: Optional[List[str]] = None,
    workers: int = 4,
) -> List[SNMPResult]:
    """
    測試單台主機的所有 SNMP community。

    相較原版的全串列逐一測試，這裡以執行緒池平行測試多個 community，
    對「community 字典很長」或「設備逾時偏久」的情況能顯著縮短單台耗時。
    仍會完整測試並回報每一個可讀 / 可寫 community，保留完整稽核證據。
    """
    if versions is None:
        versions = ["2c", "1"]

    effective_workers = max(1, min(workers, len(communities))) if communities else 1
    serial = effective_workers == 1

    if serial:
        return [
            _audit_one_community(
                host, community, write_test, timeout_sec,
                delay_sec, retries, versions, serial=True,
            )
            for community in communities
        ]

    # 並行模式：保留與輸入相同的 community 順序，方便報告閱讀
    results_by_index: Dict[int, SNMPResult] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
        future_map = {
            executor.submit(
                _audit_one_community,
                host, community, write_test, timeout_sec,
                delay_sec, retries, versions, False,
            ): idx
            for idx, community in enumerate(communities)
        }

        for future in concurrent.futures.as_completed(future_map):
            idx = future_map[future]
            try:
                results_by_index[idx] = future.result()
            except Exception as e:
                results_by_index[idx] = SNMPResult(
                    community=communities[idx],
                    readable=False,
                    writable=None,
                    sys_descr=None,
                    note=f"community 測試發生例外：{e}",
                    version=None,
                )

    return [results_by_index[i] for i in range(len(communities))]


def _classify_ftp_error(exc: BaseException) -> str:
    """
    把 FTP 登入失敗分成三類，讓「密碼真的錯」和「被設備擋掉」不再混為一談：

    - "auth" : 帳密錯誤（典型 530 Login incorrect / 430）。密碼就是不對，重試也沒用。
    - "conn" : 連線層問題（連線被拒、逾時、421 連線數過多 / 服務不可用、被重置）。
               這類是暫時性的，值得重試；也是防暴力破解 / 並行連線上限的典型徵兆。
    - "other": 其他未分類錯誤。
    """
    if isinstance(exc, ftplib.error_perm):
        msg = str(exc).strip()
        # 5xx 永久錯誤：530/430 皆為帳密問題；其餘 5xx 在登入情境下同樣視為非連線類
        return "auth"

    if isinstance(exc, ftplib.error_temp):
        # 4xx 暫時性錯誤，例如 421 Too many connections / service not available
        return "conn"

    if isinstance(exc, (socket.timeout, TimeoutError, ConnectionRefusedError,
                        ConnectionResetError, ConnectionAbortedError, EOFError, OSError)):
        return "conn"

    return "other"


def _decode_listing(raw: bytes) -> str:
    """
    目錄列表可能是任意編碼（繁中設備常見 Big5/CP950，簡中 GBK，日文 Shift-JIS…）。
    依序嘗試常見編碼，全部失敗才用 replace 保底，確保永不因解碼而丟失整份列表。
    """
    for enc in ("utf-8", "cp950", "big5", "gbk", "gb18030", "shift_jis", "euc-kr"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def _raw_list(ftp: ftplib.FTP, cmd: str) -> List[str]:
    """
    以二進位方式抓取 LIST / NLST 的原始位元組，避開 ftplib 內建以固定編碼解碼、
    一遇非 UTF-8 檔名（如 Big5 中文）就整個拋例外的問題；抓回後自行容錯解碼。
    """
    buf = bytearray()
    ftp.retrbinary(cmd, buf.extend)
    text = _decode_listing(bytes(buf)).replace("\r\n", "\n").replace("\r", "\n")
    return [line for line in text.split("\n") if line.strip()]


def _ftp_list_root(ftp: ftplib.FTP) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    列出登入後的根目錄，回傳 (file_list, error)。

    FTP 的資料連線（LIST 用）不像控制連線那麼單純：
    - 被動模式(PASV)可能因設備回報不可達的 IP、或防火牆擋資料埠而失敗。
    - 主動模式(PORT)又可能因掃描端在 NAT 後、設備連不回來而失敗。
    另外，目錄列表的位元組可能是 Big5 等非 UTF-8 編碼，若交給 ftplib 內建解碼會直接崩潰。

    策略：先被動、再主動；每種模式都用原始位元組容錯解碼；LIST 若為空再用 NLST
    交叉確認；兩者皆空視為真的空目錄；全部失敗則回傳錯誤原因，讓報告能明確區分
    「真的空目錄」與「資料連線失敗」。
    """
    errors: List[str] = []

    for pasv in (True, False):
        mode_label = "PASV" if pasv else "PORT"

        try:
            ftp.set_pasv(pasv)

            lines = _raw_list(ftp, "LIST")
            if lines:
                return lines, None

            # LIST 成功但為空，改用 NLST 交叉確認（部分伺服器 LIST 空、NLST 卻有資料）
            try:
                names = [n for n in _raw_list(ftp, "NLST") if n not in (".", "..")]
                if names:
                    return names, None
            except Exception as e:
                errors.append(f"{mode_label}/NLST:{e}")

            # 兩種列法都沒東西 → 視為真的空目錄
            return [], None

        except Exception as e:
            errors.append(f"{mode_label}:{e}")
            continue

    return None, "; ".join(errors) if errors else "列目錄失敗"


def try_ftp_login(
    host: str,
    username: str,
    password: str,
    timeout_sec: int,
    conn_retries: int = 2,
    retry_backoff: float = 0.5,
) -> FTPResult:
    """
    嘗試單組 FTP 帳密，並對「連線類失敗」自動重試。

    改良重點：
    1. 逾時交給 ftplib 的 socket timeout（同時作用於控制連線與 LIST 資料連線），
       不再另開 daemon 執行緒，避免逾時後殘留殭屍連線。
    2. 區分「帳密錯誤」與「連線問題」：帳密錯誤不重試（密碼就是不對）；連線問題
       重試最多 conn_retries 次，避免正確帳密因一次暫時性連線失敗（設備限流 / 防
       暴力）被誤判成登入失敗——這正是「密碼在字典裡卻測不出來」的常見主因之一。
    """
    banner: Optional[str] = None
    last_note: Optional[str] = None
    last_kind: str = "other"

    attempt = 0
    while attempt <= conn_retries:
        attempt += 1
        ftp = ftplib.FTP()
        # 控制通道容錯：舊設備可能在 banner / 回應中夾帶非 UTF-8（如 Big5）位元組，
        # latin-1 為全位元組對映、永不拋解碼例外；需在 connect 前設定才會套用到 welcome。
        ftp.encoding = "latin-1"

        try:
            # timeout 同時作用於控制連線與資料連線（CPython ftplib 會沿用 self.timeout）
            ftp.connect(host=host, port=21, timeout=timeout_sec)
            banner = ftp.getwelcome()
            ftp.login(user=username, passwd=password)

            # 登入成功後取得根目錄檔案列表（盡力而為，失敗不影響登入成功的判定）
            # 被動/主動雙模式嘗試，並在失敗時保留原因供報告呈現。
            file_list, list_error = _ftp_list_root(ftp)

            try:
                ftp.quit()
            except Exception:
                pass

            return FTPResult(
                username=username,
                password=password,
                success=True,
                banner=banner,
                note=None,
                file_list=file_list,
                fail_kind=None,
                list_error=list_error,
            )

        except Exception as e:
            kind = _classify_ftp_error(e)
            last_note = str(e)
            last_kind = kind

            # 帳密錯誤：密碼就是不對，直接回報，不浪費時間重試
            if kind == "auth":
                return FTPResult(
                    username=username,
                    password=password,
                    success=False,
                    banner=banner,
                    note=last_note,
                    fail_kind="auth",
                )
            # conn / other：落到下方重試

        finally:
            try:
                ftp.close()
            except Exception:
                pass

        if attempt <= conn_retries:
            time.sleep(retry_backoff)

    # 連線類失敗且重試用盡
    return FTPResult(
        username=username,
        password=password,
        success=False,
        banner=banner,
        note=last_note,
        fail_kind=last_kind,
    )


def audit_ftp_host(
    host: str,
    users: List[str],
    passwords: List[str],
    pairs: List[Tuple[str, str]],
    mode: str,
    timeout_sec: int,
    delay_sec: float,
    max_attempts: int,
    find_all: bool,
    include_anonymous: bool,
    workers: int = 8,
    conn_retries: int = 2,
) -> List[FTPResult]:
    results: List[FTPResult] = []
    test_pairs: List[Tuple[str, str]] = []

    if include_anonymous:
        test_pairs.append(("anonymous", "anonymous@example.com"))

    if mode == "pair":
        test_pairs.extend(pairs)
    else:
        test_pairs.extend(list(itertools.product(users, passwords)))

    total_generated = len(test_pairs)
    truncated = 0

    if max_attempts > 0 and total_generated > max_attempts:
        truncated = total_generated - max_attempts
        test_pairs = test_pairs[:max_attempts]
        # 截斷不再靜默：明確告知使用者有多少組被丟棄
        print(
            f"    [{host}] 注意：共產生 {total_generated} 組帳密，"
            f"因 --ftp-max-attempts={max_attempts} 只會測前 {max_attempts} 組，"
            f"已忽略 {truncated} 組（用 --ftp-max-attempts 0 可測完整份清單）"
        )

    fail_counter = {"auth": 0, "conn": 0, "other": 0}

    def _record_fail(r: FTPResult) -> None:
        k = r.fail_kind if r.fail_kind in fail_counter else "other"
        fail_counter[k] += 1

    serial = workers <= 1

    if serial:
        # 序列模式：--ftp-delay 在此真正生效，每次嘗試間確實間隔，
        # 對限制並行連線 / 有防暴力機制的嵌入式設備最安全。
        for username, password in test_pairs:
            result = try_ftp_login(
                host, username, password, timeout_sec, conn_retries=conn_retries
            )

            if result.success:
                results.append(result)
                if not find_all:
                    break
            else:
                _record_fail(result)

            if delay_sec > 0:
                time.sleep(delay_sec)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(
                    try_ftp_login, host, username, password, timeout_sec, conn_retries
                ): (username, password)
                for username, password in test_pairs
            }

            for future in concurrent.futures.as_completed(future_map):
                try:
                    result = future.result()
                except Exception:
                    continue

                if result.success:
                    results.append(result)

                    if not find_all:
                        for f in future_map:
                            f.cancel()
                        break
                else:
                    _record_fail(result)

    # FTP 埠開著卻一組都沒成功時，印出失敗原因分解，讓「密碼真的不對」與
    # 「被設備擋掉」一目了然，不必再靠猜。
    if not results:
        tested = fail_counter["auth"] + fail_counter["conn"] + fail_counter["other"]
        print(
            f"    [{host}] FTP 開啟但無成功登入：已測 {tested} 組 → "
            f"帳密錯誤(5xx) {fail_counter['auth']}、"
            f"連線被拒/逾時/限流 {fail_counter['conn']}、"
            f"其他 {fail_counter['other']}"
        )

        if fail_counter["conn"] > 0 and fail_counter["conn"] >= max(1, fail_counter["auth"] // 2):
            print(
                f"    [{host}] 提示：連線類失敗偏多，可能是設備限制並行連線或觸發防暴力鎖定。"
                f"建議 --ftp-workers 1、加大 --ftp-delay（如 1）、必要時降低 --ftp-max-attempts。"
            )
        elif mode == "wordlist" and fail_counter["auth"] == tested and tested > 0:
            print(
                f"    [{host}] 提示：全部為帳密錯誤。單字交叉模式需要「正確帳號」也在字典中，"
                f"若正確帳號不在 ftplist.txt，任何密碼都配不出正確組合。"
                f"可把正確帳號補進清單，或改用 user:password 指定帳密格式。"
            )

    return results


def risk_level(host_result: HostResult) -> str:
    snmp_readable = any(item.readable for item in host_result.snmp_results)
    snmp_writable = any(item.writable is True for item in host_result.snmp_results)
    ftp_login = any(item.success for item in host_result.ftp_results)

    if snmp_writable or ftp_login:
        return "High"

    if snmp_readable:
        return "Medium"

    if host_result.ftp_open or host_result.snmp_open:
        return "Low"

    return "Info"


def make_summary(results: List[HostResult]) -> Dict[str, int]:
    summary = {
        "total_hosts_with_open_service": len(results),
        "ftp_open_hosts": 0,
        "snmp_open_hosts": 0,
        "ftp_weak_login_hosts": 0,
        "snmp_readable_hosts": 0,
        "snmp_writable_hosts": 0,
        "high_risk_hosts": 0,
        "medium_risk_hosts": 0,
        "low_risk_hosts": 0,
    }

    for item in results:
        if item.ftp_open:
            summary["ftp_open_hosts"] += 1

        if item.snmp_open:
            summary["snmp_open_hosts"] += 1

        if any(x.success for x in item.ftp_results):
            summary["ftp_weak_login_hosts"] += 1

        if any(x.readable for x in item.snmp_results):
            summary["snmp_readable_hosts"] += 1

        if any(x.writable is True for x in item.snmp_results):
            summary["snmp_writable_hosts"] += 1

        risk = risk_level(item)

        if risk == "High":
            summary["high_risk_hosts"] += 1
        elif risk == "Medium":
            summary["medium_risk_hosts"] += 1
        elif risk == "Low":
            summary["low_risk_hosts"] += 1

    return summary


def write_json_report(
    results: List[HostResult],
    summary: Dict[str, int],
    path: str,
    mode: str,
    targets: List[str],
) -> None:
    data = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": mode,
        "targets": targets,
        "summary": summary,
        "results": [asdict(item) for item in results],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_csv_report(results: List[HostResult], path: str) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "host",
            "risk",
            "ftp_open",
            "snmp_open",
            "ftp_success_logins",
            "ftp_banner",
            "ftp_file_list",
            "snmp_readable_communities",
            "snmp_writable_communities",
            "snmp_sysdescr",
        ])

        for host_result in results:
            ftp_success = [
                f"{x.username}:{x.password}"
                for x in host_result.ftp_results
                if x.success
            ]

            ftp_banners = [
                x.banner
                for x in host_result.ftp_results
                if x.banner
            ]

            ftp_files: List[str] = []
            for x in host_result.ftp_results:
                if x.success and x.file_list:
                    ftp_files.extend(x.file_list)

            snmp_readable = [
                x.community
                for x in host_result.snmp_results
                if x.readable
            ]

            snmp_writable = [
                x.community
                for x in host_result.snmp_results
                if x.writable is True
            ]

            sysdescr_list = [
                x.sys_descr
                for x in host_result.snmp_results
                if x.readable and x.sys_descr
            ]

            writer.writerow([
                host_result.host,
                risk_level(host_result),
                host_result.ftp_open,
                host_result.snmp_open,
                "; ".join(ftp_success),
                " | ".join(ftp_banners[:3]),
                "\n".join(ftp_files),
                "; ".join(snmp_readable),
                "; ".join(snmp_writable),
                " | ".join(sysdescr_list[:3]),
            ])


def html_escape(value: object) -> str:
    if value is None:
        return ""

    return html.escape(str(value))


def write_html_report(
    results: List[HostResult],
    summary: Dict[str, int],
    path: str,
    mode: str,
    targets: List[str],
) -> None:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []

    for host_result in results:
        risk = risk_level(host_result)

        ftp_success = [
            f"{x.username}:{x.password}"
            for x in host_result.ftp_results
            if x.success
        ]

        ftp_banners = [
            x.banner
            for x in host_result.ftp_results
            if x.banner
        ]

        # 收集所有成功登入的檔案列表（帳密 + 清單）
        ftp_file_sections: List[str] = []
        for x in host_result.ftp_results:
            if not x.success:
                continue
            header = html_escape(f"{x.username}:{x.password}")
            if x.file_list is not None:
                entries = "<br>".join(html_escape(line) for line in x.file_list) if x.file_list else "（空目錄）"
            elif x.list_error:
                entries = f"（無法取得列表：{html_escape(x.list_error)}）"
            else:
                entries = "（空目錄）"
            ftp_file_sections.append(f"<b>{header}</b><br><pre style='margin:2px 0;font-size:12px'>{entries}</pre>")

        snmp_readable = [
            x.community
            for x in host_result.snmp_results
            if x.readable
        ]

        snmp_writable = [
            x.community
            for x in host_result.snmp_results
            if x.writable is True
        ]

        sysdescr_list = [
            x.sys_descr
            for x in host_result.snmp_results
            if x.readable and x.sys_descr
        ]

        rows.append(f"""
        <tr class="risk-{html_escape(risk).lower()}">
            <td>{html_escape(host_result.host)}</td>
            <td><strong>{html_escape(risk)}</strong></td>
            <td>{html_escape("OPEN" if host_result.ftp_open else "-")}</td>
            <td>{html_escape("OPEN" if host_result.snmp_open else "-")}</td>
            <td>{html_escape("; ".join(ftp_success))}</td>
            <td>{html_escape(" | ".join(ftp_banners[:3]))}</td>
            <td>{"".join(ftp_file_sections) if ftp_file_sections else ""}</td>
            <td>{html_escape("; ".join(snmp_readable))}</td>
            <td>{html_escape("; ".join(snmp_writable))}</td>
            <td>{html_escape(" | ".join(sysdescr_list[:3]))}</td>
        </tr>
        """)

    targets_html = "".join(
        f"<li>{html_escape(target)}</li>"
        for target in targets
    )

    html_doc = f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<title>SNMP / FTP 稽核報告</title>
<style>
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans TC", Arial, sans-serif;
    margin: 24px;
    color: #222;
}}

h1, h2 {{
    margin-bottom: 8px;
}}

.summary {{
    display: grid;
    grid-template-columns: repeat(4, minmax(160px, 1fr));
    gap: 12px;
    margin: 20px 0;
}}

.card {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 12px;
    background: #fafafa;
}}

.card .num {{
    font-size: 28px;
    font-weight: 700;
}}

table {{
    border-collapse: collapse;
    width: 100%;
    margin-top: 16px;
    font-size: 14px;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 8px;
    vertical-align: top;
}}

th {{
    background: #f0f0f0;
}}

.risk-high {{
    background: #ffecec;
}}

.risk-medium {{
    background: #fff8e1;
}}

.risk-low {{
    background: #eef7ff;
}}

.small {{
    color: #666;
    font-size: 13px;
}}

code {{
    background: #f4f4f4;
    padding: 2px 4px;
    border-radius: 4px;
}}
</style>
</head>
<body>
<h1>SNMP / FTP 稽核報告</h1>

<div class="small">產生時間：{html_escape(generated_at)}</div>
<div class="small">掃描模式：<code>{html_escape(mode)}</code></div>

<h2>掃描目標</h2>
<ul>
{targets_html}
</ul>

<h2>摘要</h2>
<div class="summary">
    <div class="card"><div>開啟服務主機數</div><div class="num">{summary["total_hosts_with_open_service"]}</div></div>
    <div class="card"><div>FTP 開啟主機</div><div class="num">{summary["ftp_open_hosts"]}</div></div>
    <div class="card"><div>SNMP 開啟主機</div><div class="num">{summary["snmp_open_hosts"]}</div></div>
    <div class="card"><div>FTP 弱帳密主機</div><div class="num">{summary["ftp_weak_login_hosts"]}</div></div>
    <div class="card"><div>SNMP 可讀主機</div><div class="num">{summary["snmp_readable_hosts"]}</div></div>
    <div class="card"><div>SNMP 可寫主機</div><div class="num">{summary["snmp_writable_hosts"]}</div></div>
    <div class="card"><div>High 風險主機</div><div class="num">{summary["high_risk_hosts"]}</div></div>
    <div class="card"><div>Medium 風險主機</div><div class="num">{summary["medium_risk_hosts"]}</div></div>
</div>

<h2>主機明細</h2>
<table>
<thead>
<tr>
    <th>Host</th>
    <th>Risk</th>
    <th>FTP</th>
    <th>SNMP</th>
    <th>FTP 成功帳密</th>
    <th>FTP Banner</th>
    <th>FTP 根目錄檔案列表</th>
    <th>SNMP 可讀 community</th>
    <th>SNMP 可寫 community</th>
    <th>SNMP sysDescr</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>

<h2>風險判定邏輯</h2>
<ul>
    <li><strong>High</strong>：FTP 可用弱帳密登入，或 SNMP community 可寫入。</li>
    <li><strong>Medium</strong>：SNMP community 可讀取。</li>
    <li><strong>Low</strong>：FTP 或 SNMP 連接埠開啟，但尚未驗證出弱點。</li>
</ul>

</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)


def print_console_report(results: List[HostResult], summary: Dict[str, int]) -> None:
    print("\n========== 稽核摘要 ==========")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\n========== 主機明細 ==========")

    if not results:
        print("未發現指定模式下的開啟服務。")
        return

    for item in results:
        print(f"\nHost: {item.host}")
        print(f"  Risk : {risk_level(item)}")
        print(f"  FTP  : {'OPEN' if item.ftp_open else '-'}")
        print(f"  SNMP : {'OPEN' if item.snmp_open else '-'}")

        ftp_success = [x for x in item.ftp_results if x.success]

        if ftp_success:
            print("  FTP 成功登入：")

            for login in ftp_success:
                print(f"    [+] {login.username}:{login.password}")
                if login.file_list is not None:
                    if login.file_list:
                        print("        根目錄檔案列表：")
                        for entry in login.file_list:
                            print(f"          {entry}")
                    else:
                        print("        根目錄：（空目錄）")
                elif login.list_error:
                    print(f"        根目錄：（無法取得列表：{login.list_error}）")

        snmp_readable = [x for x in item.snmp_results if x.readable]

        if snmp_readable:
            print("  SNMP 可讀 community：")

            for snmp in snmp_readable:
                writable_text = "未測試"

                if snmp.writable is True:
                    writable_text = "可寫入"
                elif snmp.writable is False:
                    writable_text = "不可寫入"
                elif snmp.writable is None:
                    writable_text = "未知"

                sysdescr = snmp.sys_descr or ""

                if len(sysdescr) > 120:
                    sysdescr = sysdescr[:120] + "..."

                version_text = f"v{snmp.version}" if snmp.version else "v?"

                print(f"    [+] {snmp.community} / {version_text} / writable={writable_text} / {sysdescr}")


def _audit_one_host(
    host: str,
    service: Dict[str, bool],
    args: argparse.Namespace,
    communities: List[str],
    ftp_users: List[str],
    ftp_passwords: List[str],
    ftp_pairs: List[Tuple[str, str]],
    ftp_mode: str,
) -> HostResult:
    print(f"\n[*] 稽核主機：{host}")

    ftp_results: List[FTPResult] = []
    snmp_results: List[SNMPResult] = []

    if args.mode in ["all", "snmp"] and service.get("snmp"):
        print(f"    [{host}] SNMP UDP/161 open，測試 community string")

        snmp_results = audit_snmp_host(
            host=host,
            communities=communities,
            write_test=args.snmp_write_test,
            timeout_sec=args.snmp_timeout,
            delay_sec=args.snmp_delay,
            retries=args.snmp_retries,
            versions=args.snmp_versions_list,
            workers=args.snmp_workers,
        )

    if args.mode in ["all", "ftp"] and service.get("ftp"):
        print(f"    [{host}] FTP TCP/21 open，測試常見帳密（{args.ftp_workers} 執行緒）")

        ftp_results = audit_ftp_host(
            host=host,
            users=ftp_users,
            passwords=ftp_passwords,
            pairs=ftp_pairs,
            mode=ftp_mode,
            timeout_sec=args.ftp_timeout,
            delay_sec=args.ftp_delay,
            max_attempts=args.ftp_max_attempts,
            find_all=args.ftp_find_all,
            include_anonymous=not args.no_anonymous,
            workers=args.ftp_workers,
            conn_retries=args.ftp_conn_retries,
        )

    return HostResult(
        host=host,
        ftp_open=service.get("ftp", False),
        snmp_open=service.get("snmp", False),
        ftp_results=ftp_results,
        snmp_results=snmp_results,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="使用 nmap 掃描多個 IP / 網段，檢查 SNMP community 與 FTP 常見帳密，並產生報告。"
    )

    parser.add_argument(
        "--mode",
        choices=["all", "snmp", "ftp"],
        default="all",
        help="掃描模式：all=SNMP+FTP，snmp=只掃 SNMP，ftp=只掃 FTP。預設：all",
    )

    parser.add_argument(
        "--iprange-file",
        default="iprange.txt",
        help="掃描範圍檔案。預設：iprange.txt",
    )

    parser.add_argument(
        "--snmp-list",
        default="snmplist.txt",
        help="SNMP community 字典檔案。預設：snmplist.txt",
    )

    parser.add_argument(
        "--ftp-list",
        default="ftplist.txt",
        help="FTP 帳密字典檔案。預設：ftplist.txt",
    )

    parser.add_argument(
        "--report-dir",
        default="reports",
        help="報告輸出目錄。預設：reports",
    )

    parser.add_argument(
        "--pn",
        action="store_true",
        help="使用 nmap -Pn，略過主機發現，直接掃描連接埠。",
    )

    parser.add_argument(
        "--host-timeout",
        default="45s",
        help="nmap 每台主機逾時，例如 30s、45s、1m。預設：45s",
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=2,
        help="nmap 掃描重試次數。預設：2",
    )

    parser.add_argument(
        "--nmap-workers",
        type=int,
        default=1,
        help="將目標網段切成幾份，平行執行多個 nmap 掃描（網段很多時可提高此值加速）。預設：1",
    )

    parser.add_argument(
        "--nmap-stats-interval",
        default="10s",
        help="nmap --stats-every 進度回報間隔，例如 5s、10s。預設：10s",
    )

    parser.add_argument(
        "--nmap-min-rate",
        type=int,
        default=None,
        help="nmap --min-rate，強制最低封包發送速率以加速掃描（過高可能造成漏包或被偵測）。預設：不設定",
    )

    parser.add_argument(
        "--nmap-timing",
        choices=["0", "1", "2", "3", "4", "5"],
        default="4",
        help="nmap 時間樣板 -T0~-T5，數字越大越快、對網路壓力越大。預設：4",
    )

    parser.add_argument(
        "--snmp-timeout",
        type=int,
        default=2,
        help="SNMP 逾時秒數。預設：2",
    )

    parser.add_argument(
        "--snmp-retries",
        type=int,
        default=1,
        help="SNMP（snmpget/snmpset）重試次數。SNMP 走 UDP 易掉包，>0 可降低偽陰性。預設：1",
    )

    parser.add_argument(
        "--snmp-versions",
        default="2c,1",
        help="要嘗試的 SNMP 版本，逗號分隔，依序測試，任一成功即算可讀。預設：2c,1（同時涵蓋只支援 v1 的舊設備）",
    )

    parser.add_argument(
        "--snmp-workers",
        type=int,
        default=4,
        help="每台主機同時測試的 SNMP community 執行緒數。設 1 為串列並套用 --snmp-delay。預設：4",
    )

    parser.add_argument(
        "--snmp-delay",
        type=float,
        default=0.1,
        help="每次 SNMP 測試間隔秒數（僅在 --snmp-workers=1 串列模式下生效）。預設：0.1",
    )

    parser.add_argument(
        "--snmp-write-test",
        action="store_true",
        help="啟用 SNMP 寫入測試。會將 sysContact.0 的原值寫回同一個值。",
    )

    parser.add_argument(
        "--ftp-timeout",
        type=int,
        default=4,
        help="FTP 連線逾時秒數。預設：4",
    )

    parser.add_argument(
        "--ftp-delay",
        type=float,
        default=0.2,
        help="每次 FTP 登入測試間隔秒數（在 --ftp-workers 1 序列模式下生效，可避開設備限流）。預設：0.2",
    )

    parser.add_argument(
        "--ftp-conn-retries",
        type=int,
        default=2,
        help="FTP 遇到連線類錯誤（被拒/逾時/限流）時的重試次數；帳密錯誤不重試。預設：2",
    )

    parser.add_argument(
        "--ftp-max-attempts",
        type=int,
        default=150,
        help="每台 FTP 主機最多嘗試次數。0 代表不限制。預設：150",
    )

    parser.add_argument(
        "--ftp-find-all",
        action="store_true",
        help="找到第一組成功帳密後仍繼續測試其他組合。",
    )

    parser.add_argument(
        "--no-anonymous",
        action="store_true",
        help="不測試 anonymous FTP。",
    )

    parser.add_argument(
        "--ftp-workers",
        type=int,
        default=8,
        help="每台主機同時測試的 FTP 帳密執行緒數。數字越大速度越快，對設備壓力也越大。預設：8",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="同時稽核的主機數量（主機層級平行）。預設：4",
    )

    args = parser.parse_args()

    # 解析並驗證 --snmp-versions（例如 "2c,1"）成清單，供 snmpget/snmpset 依序嘗試
    allowed_versions = {"1", "2c"}
    versions_list: List[str] = []
    for token in args.snmp_versions.split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token not in allowed_versions:
            parser.error(f"--snmp-versions 只支援 1 與 2c，收到不支援的值：{token}")
        if token not in versions_list:
            versions_list.append(token)

    if not versions_list:
        parser.error("--snmp-versions 至少要指定一個版本（1 或 2c）")

    args.snmp_versions_list = versions_list

    return args


def main() -> None:
    args = parse_args()

    require_binary("nmap")

    if args.mode in ["all", "snmp"]:
        require_binary("snmpget")

        if args.snmp_write_test:
            require_binary("snmpset")

    targets = read_ip_ranges(args.iprange_file)

    communities: List[str] = []
    ftp_users: List[str] = []
    ftp_passwords: List[str] = []
    ftp_pairs: List[Tuple[str, str]] = []
    ftp_mode = "wordlist"

    if args.mode in ["all", "snmp"]:
        communities = read_snmp_communities(args.snmp_list)

    if args.mode in ["all", "ftp"]:
        ftp_users, ftp_passwords, ftp_pairs, ftp_mode = read_ftp_list(args.ftp_list)

    print("[*] 載入設定")
    print(f"    掃描模式           : {args.mode}")
    print(f"    IP / 網段數量      : {len(targets)}")

    if args.mode in ["all", "snmp"]:
        print(f"    SNMP community 數量: {len(communities)}")
        print(f"    SNMP 測試版本      : {','.join(args.snmp_versions_list)}")
        print(f"    SNMP 重試次數      : {args.snmp_retries}")
        print(f"    SNMP 執行緒 / 主機  : {args.snmp_workers}")

    if args.mode in ["all", "ftp"]:
        if ftp_mode == "pair":
            print("    FTP 模式           : 指定帳密")
            print(f"    FTP 帳密組數       : {len(ftp_pairs)}")
        else:
            print("    FTP 模式           : 單字交叉組合")
            print(f"    FTP 帳號數         : {len(ftp_users)}")
            print(f"    FTP 密碼數         : {len(ftp_passwords)}")
            print(f"    FTP 最大組合數     : {len(ftp_users) * len(ftp_passwords)}")
        print(f"    FTP 執行緒 / 主機   : {args.ftp_workers}")

    print(f"    主機平行執行緒     : {args.workers}")
    print(f"    nmap 並行分片數    : {args.nmap_workers}")
    print(f"    nmap 進度回報間隔  : {args.nmap_stats_interval}")
    print(f"    nmap 時間樣板      : -T{args.nmap_timing}")

    discovered = nmap_scan_targets(
        targets=targets,
        mode=args.mode,
        host_timeout=args.host_timeout,
        max_retries=args.max_retries,
        pn=args.pn,
        nmap_workers=args.nmap_workers,
        stats_interval=args.nmap_stats_interval,
        min_rate=args.nmap_min_rate,
        timing=args.nmap_timing,
    )

    final_results: List[HostResult] = []

    total_hosts = len(discovered)
    print(f"\n[*] nmap 探索完成，共 {total_hosts} 台主機需要稽核（主機平行執行緒={args.workers}）")

    audit_completed = 0
    audit_completed_lock = threading.Lock()
    audit_start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        host_futures = {
            executor.submit(
                _audit_one_host,
                host, service, args,
                communities, ftp_users, ftp_passwords, ftp_pairs, ftp_mode,
            ): host
            for host, service in sorted(discovered.items())
        }

        for future in concurrent.futures.as_completed(host_futures):
            host = host_futures[future]
            final_results.append(future.result())

            with audit_completed_lock:
                audit_completed += 1
                done = audit_completed

            elapsed = time.time() - audit_start_time
            avg = elapsed / done if done else 0
            remaining = (total_hosts - done) * avg
            percent = (done * 100 // total_hosts) if total_hosts else 100

            print(
                f"[進度] 主機稽核 {done}/{total_hosts} 完成（{percent}%）"
                f"最新完成：{host}，已耗時 {elapsed:.0f}s，預估剩餘 {remaining:.0f}s"
            )

    # 依 IP 排序，保持報告順序一致
    final_results.sort(key=lambda r: ipaddress.IPv4Address(r.host))

    summary = make_summary(final_results)

    os.makedirs(args.report_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"snmp_ftp_audit_{args.mode}_{timestamp}"

    json_path = os.path.join(args.report_dir, f"{base_name}.json")
    csv_path = os.path.join(args.report_dir, f"{base_name}.csv")
    html_path = os.path.join(args.report_dir, f"{base_name}.html")

    write_json_report(
        results=final_results,
        summary=summary,
        path=json_path,
        mode=args.mode,
        targets=targets,
    )

    write_csv_report(
        results=final_results,
        path=csv_path,
    )

    write_html_report(
        results=final_results,
        summary=summary,
        path=html_path,
        mode=args.mode,
        targets=targets,
    )

    print_console_report(final_results, summary)

    print("\n========== 報告輸出 ==========")
    print(f"JSON: {json_path}")
    print(f"CSV : {csv_path}")
    print(f"HTML: {html_path}")


if __name__ == "__main__":
    main()
