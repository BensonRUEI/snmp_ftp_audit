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
import shutil
import subprocess
import sys
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


@dataclass
class FTPResult:
    username: str
    password: str
    success: bool
    banner: Optional[str]
    note: Optional[str]
    file_list: Optional[List[str]] = None


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

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            item = line.strip()

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


def nmap_scan_targets(
    targets: List[str],
    mode: str,
    host_timeout: str,
    max_retries: int,
    pn: bool,
) -> Dict[str, Dict[str, bool]]:
    discovered: Dict[str, Dict[str, bool]] = {}

    ports = build_nmap_ports(mode)
    scan_flags = build_nmap_scan_flags(mode)

    cmd = [
        "nmap",
        "-oX",
        "-",
        *scan_flags,
        "--open",
        "-p",
        ports,
        "--max-retries",
        str(max_retries),
        "--host-timeout",
        host_timeout,
    ]

    if pn:
        cmd.append("-Pn")

    cmd.extend(targets)

    print("[*] 執行 nmap 掃描")
    print(f"    模式：{mode}")
    print(f"    {' '.join(cmd)}")

    rc, stdout, stderr = run_command(cmd, timeout=7200)

    if rc != 0:
        print("[!] nmap 掃描失敗。請確認是否使用 sudo 執行，以及目標格式是否正確。", file=sys.stderr)

        if stderr:
            print(stderr, file=sys.stderr)

        sys.exit(1)

    try:
        root = ET.fromstring(stdout)
    except ET.ParseError as e:
        print(f"[!] nmap XML 解析失敗：{e}", file=sys.stderr)
        sys.exit(1)

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")

        if addr_elem is None:
            continue

        ip = addr_elem.attrib.get("addr")

        if not ip:
            continue

        ftp_open = False
        snmp_open = False

        ports_elem = host.find("ports")

        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                proto = port.attrib.get("protocol")
                portid = port.attrib.get("portid")

                state_elem = port.find("state")

                if state_elem is None:
                    continue

                state = state_elem.attrib.get("state")

                if state != "open":
                    continue

                if proto == "tcp" and portid == "21":
                    ftp_open = True

                if proto == "udp" and portid == "161":
                    snmp_open = True

        if ftp_open or snmp_open:
            discovered[ip] = {
                "ftp": ftp_open,
                "snmp": snmp_open,
            }

    return discovered


def snmp_get(
    host: str,
    community: str,
    oid: str,
    timeout_sec: int,
) -> Tuple[bool, Optional[str], Optional[str]]:
    cmd = [
        "snmpget",
        "-v2c",
        "-c",
        community,
        "-t",
        str(timeout_sec),
        "-r",
        "0",
        "-Oqv",
        host,
        oid,
    ]

    rc, stdout, stderr = run_command(cmd, timeout=timeout_sec + 3)

    if rc == 0 and stdout:
        value = stdout.strip()

        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        return True, value, None

    return False, None, stderr or stdout or "SNMP read failed"


def snmp_set_same_value(
    host: str,
    community: str,
    oid: str,
    value: str,
    timeout_sec: int,
) -> Tuple[Optional[bool], Optional[str]]:
    """
    保守寫入測試：
    先讀 sysContact.0，再把相同值寫回 sysContact.0。

    注意：
    這仍然是 SNMP SET 操作。
    建議只在授權維護時段或測試環境啟用。
    """
    cmd = [
        "snmpset",
        "-v2c",
        "-c",
        community,
        "-t",
        str(timeout_sec),
        "-r",
        "0",
        host,
        oid,
        "s",
        value,
    ]

    rc, stdout, stderr = run_command(cmd, timeout=timeout_sec + 3)

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


def audit_snmp_host(
    host: str,
    communities: List[str],
    write_test: bool,
    timeout_sec: int,
    delay_sec: float,
) -> List[SNMPResult]:
    results: List[SNMPResult] = []

    for community in communities:
        readable, sys_descr, read_note = snmp_get(
            host=host,
            community=community,
            oid=SNMP_SYS_DESCR_OID,
            timeout_sec=timeout_sec,
        )

        if not readable:
            results.append(
                SNMPResult(
                    community=community,
                    readable=False,
                    writable=None,
                    sys_descr=None,
                    note=read_note,
                )
            )

            if delay_sec > 0:
                time.sleep(delay_sec)

            continue

        writable: Optional[bool] = None
        note: Optional[str] = None

        if write_test:
            contact_ok, contact_value, contact_note = snmp_get(
                host=host,
                community=community,
                oid=SNMP_SYS_CONTACT_OID,
                timeout_sec=timeout_sec,
            )

            if contact_ok and contact_value is not None:
                writable, note = snmp_set_same_value(
                    host=host,
                    community=community,
                    oid=SNMP_SYS_CONTACT_OID,
                    value=contact_value,
                    timeout_sec=timeout_sec,
                )
            else:
                writable = None
                note = f"可讀，但無法讀取 sysContact.0 進行保守寫入測試：{contact_note}"

        results.append(
            SNMPResult(
                community=community,
                readable=True,
                writable=writable,
                sys_descr=sys_descr,
                note=note,
            )
        )

        if delay_sec > 0:
            time.sleep(delay_sec)

    return results


def try_ftp_login(
    host: str,
    username: str,
    password: str,
    timeout_sec: int,
) -> FTPResult:
    # 整體逾時上限：connect + banner + USER + PASS + quit 各最多 timeout_sec，
    # 加總最壞情況約 5x，設 4x 以避免設備太慢時無限卡住。
    overall_timeout = timeout_sec * 4
    result_holder: List[FTPResult] = []

    def _do() -> None:
        ftp = ftplib.FTP()
        banner = None

        try:
            ftp.connect(host=host, port=21, timeout=timeout_sec)
            banner = ftp.getwelcome()
            ftp.login(user=username, passwd=password)

            # 登入成功後取得根目錄檔案列表
            file_list: Optional[List[str]] = None
            try:
                listing: List[str] = []
                ftp.dir(listing.append)
                file_list = listing if listing else []
            except Exception:
                file_list = []

            try:
                ftp.quit()
            except Exception:
                pass

            result_holder.append(FTPResult(
                username=username,
                password=password,
                success=True,
                banner=banner,
                note=None,
                file_list=file_list,
            ))

        except Exception as e:
            result_holder.append(FTPResult(
                username=username,
                password=password,
                success=False,
                banner=banner,
                note=str(e),
            ))

        finally:
            try:
                ftp.close()
            except Exception:
                pass

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=overall_timeout)

    if result_holder:
        return result_holder[0]

    # 執行緒仍在跑表示整體逾時，daemon=True 確保程式結束時不阻擋
    return FTPResult(
        username=username,
        password=password,
        success=False,
        banner=None,
        note=f"整體連線逾時（>{overall_timeout}s）",
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
) -> List[FTPResult]:
    results: List[FTPResult] = []
    test_pairs: List[Tuple[str, str]] = []

    if include_anonymous:
        test_pairs.append(("anonymous", "anonymous@example.com"))

    if mode == "pair":
        test_pairs.extend(pairs)
    else:
        test_pairs.extend(list(itertools.product(users, passwords)))

    if max_attempts > 0:
        test_pairs = test_pairs[:max_attempts]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # 一次提交所有任務；executor 依 workers 限制同時執行數，
        # 未啟動的任務可透過 cancel() 跳過，達到 find_all=False 快速中止。
        future_map = {
            executor.submit(try_ftp_login, host, username, password, timeout_sec): (username, password)
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
                    # 取消尚未啟動的佇列任務
                    for f in future_map:
                        f.cancel()
                    break

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
            if x.success and x.file_list is not None:
                header = html_escape(f"{x.username}:{x.password}")
                entries = "<br>".join(html_escape(line) for line in x.file_list) if x.file_list else "（空目錄）"
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

                print(f"    [+] {snmp.community} / writable={writable_text} / {sysdescr}")


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
        "--snmp-timeout",
        type=int,
        default=2,
        help="SNMP 逾時秒數。預設：2",
    )

    parser.add_argument(
        "--snmp-delay",
        type=float,
        default=0.1,
        help="每次 SNMP 測試間隔秒數。預設：0.1",
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
        help="每次 FTP 登入測試間隔秒數。預設：0.2",
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

    return parser.parse_args()


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

    discovered = nmap_scan_targets(
        targets=targets,
        mode=args.mode,
        host_timeout=args.host_timeout,
        max_retries=args.max_retries,
        pn=args.pn,
    )

    final_results: List[HostResult] = []

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
            final_results.append(future.result())

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