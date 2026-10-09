#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path


BASE_DIR = Path("/opt/check_ssl")
NGINX_DIR = Path("/www/server/panel/vhost/nginx")
WWWROOT_DIR = Path("/www/wwwroot")

LOG_DIR = BASE_DIR / "logs"
STATE_DIR = BASE_DIR / "state"

OUTPUT_FILE = BASE_DIR / "domain.txt"
RUN_LOG = LOG_DIR / "run.log"
ABNORMAL_LOG = LOG_DIR / "abnormal.log"
STATE_FILE = STATE_DIR / "last_run.json"


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)

SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);", re.I)
ROOT_RE = re.compile(r"\broot\s+([^;]+);", re.I)

LISTEN_443_RE = re.compile(
    r"\blisten\s+(?:\[[^\]]+\]:)?443\b[^;]*;",
    re.I,
)

LISTEN_443_SSL_RE = re.compile(
    r"\blisten\s+(?:\[[^\]]+\]:)?443\b[^;]*\bssl\b[^;]*;",
    re.I,
)

SSL_CERT_RE = re.compile(
    r"\bssl_certificate\s+([^;]+);",
    re.I,
)

SSL_KEY_RE = re.compile(
    r"\bssl_certificate_key\s+([^;]+);",
    re.I,
)


SKIP_NAMES = {
    "default.conf",
    "0.default.conf",
    "phpfpm_status.conf",
}


def ensure_dirs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def log(message, abnormal=False):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{now} | {message}\n"

    target = ABNORMAL_LOG if abnormal else RUN_LOG

    with target.open("a", encoding="utf-8") as f:
        f.write(line)


def strip_comments(text):
    """
    删除 Nginx # 注释内容。
    避免被注释掉的 listen 443 ssl / ssl_certificate 被误判。
    """
    lines = []

    for line in text.splitlines():
        pos = line.find("#")

        if pos >= 0:
            line = line[:pos]

        lines.append(line)

    return "\n".join(lines)


def clean_token(value):
    return value.strip().strip('"').strip("'")


def valid_domain(name):
    name = name.strip().rstrip(".").lower()

    if not name:
        return False

    if name in {"_", "localhost"}:
        return False

    if name.startswith("*."):
        name = name[2:]

    return bool(DOMAIN_RE.match(name))


def extract_domains(text, conf_path):
    """
    从 server_name 中提取域名。
    server_name 无有效域名时，使用 xxx.com.conf 文件名兜底。
    """

    names = []

    for match in SERVER_NAME_RE.finditer(text):

        for token in match.group(1).split():

            token = clean_token(token).rstrip(".").lower()

            if token.startswith("*."):
                token = token[2:]

            if valid_domain(token):
                names.append(token)

    if not names:

        if conf_path.name.lower().endswith(".conf"):
            stem = conf_path.name[:-5].lower()
        else:
            stem = conf_path.stem.lower()

        if valid_domain(stem):
            names.append(stem)

    return sorted(set(names))


def choose_site_domain(domains, conf_path):
    """
    确定当前 conf 对应的主站域名。

    优先：
    1. conf 文件名
    2. 非 www/m/wap/3g 域名
    3. 最短层级域名
    """

    if not domains:
        return None

    if conf_path.name.lower().endswith(".conf"):
        stem = conf_path.name[:-5].lower()
    else:
        stem = conf_path.stem.lower()

    if stem in domains:
        return stem

    common_prefixes = (
        "www.",
        "m.",
        "wap.",
        "3g.",
    )

    candidates = [
        domain
        for domain in domains
        if not domain.startswith(common_prefixes)
    ]

    if candidates:
        return min(
            candidates,
            key=lambda d: (
                d.count("."),
                len(d),
                d,
            ),
        )

    return min(
        domains,
        key=lambda d: (
            d.count("."),
            len(d),
            d,
        ),
    )


def extract_server_blocks(text):
    """
    提取每个 server { ... }。

    非常重要：
    一个宝塔 conf 文件可能存在多个 server 块，
    不能因为其中另一个域名有 SSL，
    就误判当前域名已经配置 SSL。
    """

    blocks = []

    pos = 0

    pattern = re.compile(
        r"\bserver\s*\{",
        re.I,
    )

    while True:

        match = pattern.search(text, pos)

        if not match:
            break

        start = match.start()

        brace = text.find(
            "{",
            match.start(),
            match.end(),
        )

        depth = 0
        end = None
        i = brace

        while i < len(text):

            ch = text[i]

            if ch == "{":
                depth += 1

            elif ch == "}":

                depth -= 1

                if depth == 0:

                    end = i + 1

                    break

            i += 1

        if end is None:

            blocks.append(text[start:])

            break

        blocks.append(
            text[start:end]
        )

        pos = end

    return blocks


def domains_in_block(block):
    names = []

    for match in SERVER_NAME_RE.finditer(block):

        for token in match.group(1).split():

            token = clean_token(
                token
            ).rstrip(".").lower()

            if token.startswith("*."):
                token = token[2:]

            if valid_domain(token):
                names.append(token)

    return sorted(set(names))


def classify_ssl(text):
    """
    SSL 分类：

    ssl
        已经配置 SSL

    no_ssl
        明确没有 SSL

    abnormal
        有 443 或证书残留，但配置不完整
    """

    has_443 = bool(
        LISTEN_443_RE.search(text)
    )

    has_443_ssl = bool(
        LISTEN_443_SSL_RE.search(text)
    )

    has_cert = bool(
        SSL_CERT_RE.search(text)
    )

    has_key = bool(
        SSL_KEY_RE.search(text)
    )

    # 完整 SSL
    if has_443 and has_cert and has_key:

        return (
            "ssl",
            "443 + ssl_certificate + ssl_certificate_key",
        )

    # listen 443 ssl 存在，但证书不完整
    if has_443_ssl:

        return (
            "abnormal",
            (
                "listen 443 ssl 存在，"
                f"但证书配置不完整"
                f"(cert={has_cert}, key={has_key})"
            ),
        )

    # 有证书残留，但没有完整 443 SSL
    if has_cert or has_key:

        return (
            "abnormal",
            (
                "存在证书相关配置，"
                "但未形成完整 SSL"
                f"(cert={has_cert}, "
                f"key={has_key}, "
                f"listen443={has_443})"
            ),
        )

    # 单纯监听 443
    if has_443:

        return (
            "abnormal",
            (
                "存在 listen 443，"
                "但未发现 "
                "ssl_certificate / "
                "ssl_certificate_key"
            ),
        )

    return (
        "no_ssl",
        "未发现有效 443 SSL 配置",
    )


def scan_one(conf_path):
    """
    扫描单个 Nginx conf。
    """

    try:

        raw = conf_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

    except OSError as exc:

        return {
            "status": "error",
            "domain": None,
            "reason": f"读取失败: {exc}",
            "conf": str(conf_path),
        }

    text = strip_comments(raw)

    domains = extract_domains(
        text,
        conf_path,
    )

    domain = choose_site_domain(
        domains,
        conf_path,
    )

    if not domain:

        return {
            "status": "skip",
            "domain": None,
            "reason": "未识别到有效域名",
            "conf": str(conf_path),
        }

    server_blocks = extract_server_blocks(text)

    related_blocks = [
        block
        for block in server_blocks
        if domain in domains_in_block(block)
    ]

    # 特殊配置兜底
    if not related_blocks:

        if server_blocks:
            related_blocks = server_blocks
        else:
            related_blocks = [text]

    classifications = [
        classify_ssl(block)
        for block in related_blocks
    ]

    # 只要与当前域名关联的 server 块中
    # 有完整 SSL，即认为站点已配置 SSL。
    if any(
        status == "ssl"
        for status, _ in classifications
    ):

        ssl_status = "ssl"

        reason = (
            "关联 server 块存在完整 443 SSL 配置"
        )

    elif any(
        status == "abnormal"
        for status, _ in classifications
    ):

        ssl_status = "abnormal"

        reasons = sorted({
            reason
            for status, reason in classifications
            if status == "abnormal"
        })

        reason = "；".join(reasons)

    else:

        ssl_status = "no_ssl"

        reason = (
            "关联 server 块未发现有效 443 SSL 配置"
        )

    root = ""

    for block in related_blocks:

        root_match = ROOT_RE.search(block)

        if root_match:

            root = clean_token(
                root_match.group(1)
            )

            break

    expected_root = (
        WWWROOT_DIR / domain
    )

    if root.startswith("/"):
        root_exists = Path(root).is_dir()
    else:
        root_exists = expected_root.is_dir()

    return {
        "status": ssl_status,
        "domain": domain,
        "reason": reason,
        "conf": str(conf_path),
        "root": root,
        "root_exists": root_exists,
    }


def atomic_write_lines(path, lines):
    """
    原子写 domain.txt。

    扫描失败或中断时，
    尽量避免留下半截 domain.txt。
    """

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:

            for item in lines:
                f.write(item + "\n")

            f.flush()

            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp_name,
            path,
        )

    except Exception:

        try:
            os.unlink(tmp_name)
        except OSError:
            pass

        raise


def atomic_write_json(path, data):
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:

            json.dump(
                data,
                f,
                ensure_ascii=False,
                indent=2,
            )

            f.write("\n")

            f.flush()

            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp_name,
            path,
        )

    except Exception:

        try:
            os.unlink(tmp_name)
        except OSError:
            pass

        raise


def list_conf_files():
    """
    高效扫描 Nginx conf。
    """

    files = []

    with os.scandir(NGINX_DIR) as entries:

        for entry in entries:

            if not entry.is_file(
                follow_symlinks=False
            ):
                continue

            name = entry.name

            if not name.lower().endswith(
                ".conf"
            ):
                continue

            if name.lower() in SKIP_NAMES:
                continue

            files.append(
                Path(entry.path)
            )

    files.sort(
        key=lambda p: p.name.lower()
    )

    return files


def run_scan(verbose=False):
    ensure_dirs()

    if not NGINX_DIR.is_dir():

        print(
            f"[ERROR] Nginx 配置目录不存在: "
            f"{NGINX_DIR}",
            file=sys.stderr,
        )

        return 2

    start = datetime.now()

    log("=" * 70)

    log(
        f"开始扫描 Nginx 配置目录: "
        f"{NGINX_DIR}"
    )

    try:

        conf_files = list_conf_files()

    except OSError as exc:

        log(
            f"扫描目录失败: {exc}",
            abnormal=True,
        )

        print(
            f"[ERROR] 扫描目录失败: {exc}",
            file=sys.stderr,
        )

        return 2

    no_ssl = set()

    stats = {
        "configs": len(conf_files),
        "ssl": 0,
        "no_ssl": 0,
        "abnormal": 0,
        "skip": 0,
        "error": 0,
    }

    for conf in conf_files:

        result = scan_one(conf)

        status = result["status"]

        domain = (
            result.get("domain")
            or "-"
        )

        if status == "no_ssl":

            no_ssl.add(domain)

            stats["no_ssl"] += 1

        elif status == "ssl":

            stats["ssl"] += 1

        elif status == "abnormal":

            stats["abnormal"] += 1

            log(
                (
                    f"{domain} | "
                    f"{result['conf']} | "
                    f"{result['reason']}"
                ),
                abnormal=True,
            )

        elif status == "skip":

            stats["skip"] += 1

            log(
                (
                    f"跳过 | "
                    f"{result['conf']} | "
                    f"{result['reason']}"
                ),
                abnormal=True,
            )

        else:

            stats["error"] += 1

            log(
                (
                    f"错误 | "
                    f"{result['conf']} | "
                    f"{result['reason']}"
                ),
                abnormal=True,
            )

        if verbose:

            print(
                f"[{status:8}] "
                f"{domain:35} "
                f"{result['reason']}"
            )

    domains = sorted(no_ssl)

    try:

        atomic_write_lines(
            OUTPUT_FILE,
            domains,
        )

    except OSError as exc:

        log(
            f"写入 domain.txt 失败: {exc}",
            abnormal=True,
        )

        print(
            (
                f"[ERROR] 写入 "
                f"{OUTPUT_FILE} "
                f"失败: {exc}"
            ),
            file=sys.stderr,
        )

        return 3

    elapsed = (
        datetime.now() - start
    ).total_seconds()

    state = {
        "time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "nginx_dir": str(NGINX_DIR),
        "output": str(OUTPUT_FILE),
        "stats": stats,
        "unique_no_ssl": len(domains),
        "elapsed_seconds": round(
            elapsed,
            3,
        ),
    }

    try:

        atomic_write_json(
            STATE_FILE,
            state,
        )

    except OSError as exc:

        log(
            f"写入运行状态失败: {exc}",
            abnormal=True,
        )

    log(
        (
            f"扫描完成 | "
            f"conf={stats['configs']} "
            f"ssl={stats['ssl']} "
            f"no_ssl={stats['no_ssl']} "
            f"unique_no_ssl={len(domains)} "
            f"abnormal={stats['abnormal']} "
            f"skip={stats['skip']} "
            f"error={stats['error']} "
            f"elapsed={elapsed:.3f}s"
        )
    )

    print()

    print("扫描完成")

    print(
        f"  配置文件："
        f"{stats['configs']}"
    )

    print(
        f"  已配置SSL："
        f"{stats['ssl']}"
    )

    print(
        f"  未配置SSL："
        f"{stats['no_ssl']}"
        f"（去重后 {len(domains)}）"
    )

    print(
        f"  异常配置："
        f"{stats['abnormal']}"
    )

    print(
        f"  跳过配置："
        f"{stats['skip']}"
    )

    print(
        f"  读取错误："
        f"{stats['error']}"
    )

    print(
        f"  输出文件："
        f"{OUTPUT_FILE}"
    )

    print(
        f"  异常日志："
        f"{ABNORMAL_LOG}"
    )

    print(
        f"  耗时："
        f"{elapsed:.3f} 秒"
    )

    return 0


def check_domain(domain):
    """
    单独检查指定域名。
    不生成 domain.txt。
    """

    ensure_dirs()

    domain = (
        domain.strip()
        .lower()
        .rstrip(".")
    )

    if not valid_domain(domain):

        print(
            f"[ERROR] 无效域名: {domain}",
            file=sys.stderr,
        )

        return 2

    if not NGINX_DIR.is_dir():

        print(
            f"[ERROR] Nginx 配置目录不存在: "
            f"{NGINX_DIR}",
            file=sys.stderr,
        )

        return 2

    exact = (
        NGINX_DIR
        / f"{domain}.conf"
    )

    if exact.is_file():

        candidates = [exact]

    else:

        candidates = list_conf_files()

    matches = []

    for conf in candidates:

        result = scan_one(conf)

        if result.get("domain") == domain:
            matches.append(result)

    if not matches:

        print(
            f"未找到站点配置：{domain}"
        )

        return 1

    for result in matches:

        print(
            f"域名：{domain}"
        )

        print(
            f"配置：{result['conf']}"
        )

        print(
            f"状态：{result['status']}"
        )

        print(
            f"原因：{result['reason']}"
        )

        if result.get("root"):

            print(
                f"root：{result['root']}"
            )

        print()

    return 0


def main():

    parser = argparse.ArgumentParser(
        description=(
            "只读扫描宝塔 Nginx 站点配置，"
            "导出未配置 SSL 的域名。"
        )
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="显示每个站点的扫描结果",
    )

    parser.add_argument(
        "--check",
        metavar="DOMAIN",
        help=(
            "只检查指定域名，"
            "不生成 domain.txt"
        ),
    )

    args = parser.parse_args()

    if args.check:

        return check_domain(
            args.check
        )

    return run_scan(
        verbose=args.verbose
    )


if __name__ == "__main__":
    sys.exit(main())