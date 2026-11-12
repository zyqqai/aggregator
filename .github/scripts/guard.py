# -*- coding: utf-8 -*-
"""Gist 订阅守卫：备份 / 校验 / 回滚。

用法：
    python .github/scripts/guard.py backup     # 运行前备份 Gist 里已有的订阅文件
    python .github/scripts/guard.py normalize  # 修正 Clash 里的非标准 !<str> 标签
    python .github/scripts/guard.py verify     # 运行后校验新生成的内容是否可用
    python .github/scripts/guard.py restore    # 失败时用备份覆盖回去，保留上一次结果

仅依赖标准库，Gist 凭据从环境变量 PUSH_TOKEN 读取。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com/gists"
CONFIG = os.environ.get("SUBSCRIBE_CONF", "subscribe/free-config.json")
BACKUP_DIR = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "aggregator-backup")
THRESHOLD = {"v2ray": 5, "clash": 10, "singbox": 5}


def token() -> str:
    value = (os.environ.get("PUSH_TOKEN") or "").strip()
    if not value:
        print("[guard] 缺少 PUSH_TOKEN 环境变量", file=sys.stderr)
        sys.exit(2)
    return value


def storage_items() -> dict[str, dict[str, str]]:
    with open(CONFIG, "r", encoding="utf-8") as fp:
        raw = json.load(fp)
    items = raw.get("storage", {}).get("items", {})
    return {k: v for k, v in items.items() if isinstance(v, dict) and v.get("gist_id")}


def request(url: str, method: str = "GET", payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    last = None
    for attempt in range(3):
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token()}",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "aggregator-guard",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = exc
            # 409 通常是并发写同一个 gist，稍等重试即可
            if exc.code not in (409, 429, 500, 502, 503):
                raise
        except urllib.error.URLError as exc:
            last = exc
        time.sleep(2 + attempt * 2)
    raise last if last else RuntimeError("request failed")


def fetch_gist(gist_id: str) -> dict[str, str]:
    """返回 {filename: content}，大文件走 raw_url 兜底。"""
    detail = request(f"{API}/{gist_id}")
    result = {}
    for name, meta in (detail.get("files") or {}).items():
        content = meta.get("content") or ""
        if meta.get("truncated") and meta.get("raw_url"):
            with urllib.request.urlopen(meta["raw_url"], timeout=60) as resp:
                content = resp.read().decode("utf-8", "ignore")
        result[name] = content
    return result


def cmd_backup() -> int:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    saved = 0
    for gist_id in {item["gist_id"] for item in storage_items().values()}:
        try:
            files = fetch_gist(gist_id)
        except Exception as exc:  # noqa: BLE001
            print(f"[guard] 备份 {gist_id} 失败（首次运行属正常）：{exc}")
            continue
        for name, content in files.items():
            if not content:
                continue
            with open(os.path.join(BACKUP_DIR, f"{gist_id}__{name}"), "w", encoding="utf-8") as fp:
                fp.write(content)
            saved += 1
    print(f"[guard] 备份完成，文件数：{saved}")
    return 0


def count_v2ray(text: str) -> int:
    body = text.strip()
    if not body:
        return 0
    candidate = body.replace("\n", "").strip()
    try:
        decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4)).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        decoded = body
    schemes = ("vmess://", "vless://", "ss://", "ssr://", "trojan://", "hysteria2://", "hy2://", "tuic://", "anytls://")
    return sum(1 for line in decoded.splitlines() if line.strip().startswith(schemes))


def count_clash(text: str) -> int:
    try:
        import yaml  # noqa: PLC0415

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return len(data.get("proxies") or [])
        if isinstance(data, list):
            # subconverter 的 list 模式会直接输出代理数组
            return len(data)
        return 0
    except Exception:  # noqa: BLE001
        return max(text.count("- name:"), text.count("- {name"))


def count_singbox(text: str) -> int:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return 0
    outbounds = data.get("outbounds") or []
    return sum(1 for item in outbounds if isinstance(item, dict) and item.get("type") not in ("selector", "urltest", "direct", "block", "dns"))


def cmd_normalize() -> int:
    """subconverter 会给数字型字符串加 `!<str>` 标签，这不是合法 YAML（Go/Python 解析器都会报错），
    换成等价的 `!!str`，让 Clash / Mihomo 系列客户端都能正常解析。"""
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        print("[guard] 未安装 PyYAML，跳过 clash 规范化")
        return 0

    failed = False
    for key, item in storage_items().items():
        filename = item.get("filename", "")
        if "clash" not in filename.lower():
            continue
        gist_id = item["gist_id"]
        try:
            content = fetch_gist(gist_id).get(filename, "")
        except Exception as exc:  # noqa: BLE001
            print(f"[guard] 读取 {filename} 失败：{exc}")
            failed = True
            continue

        fixed = content.replace("!<str>", "!!str")
        try:
            data = yaml.safe_load(fixed)
            count = len(data.get("proxies") or []) if isinstance(data, dict) else len(data or [])
        except Exception as exc:  # noqa: BLE001
            print(f"[guard] {filename} 不是合法 YAML：{exc}")
            failed = True
            continue

        if fixed != content:
            request(f"{API}/{gist_id}", method="PATCH", payload={"files": {filename: {"content": fixed}}})
            print(f"[guard] {filename} 已修正 !<str> 标签，YAML 解析出 {count} 个节点")
        else:
            print(f"[guard] {filename} 无需修正，YAML 解析出 {count} 个节点")
    return 1 if failed else 0


def kind_of(filename: str) -> str:
    name = filename.lower()
    for kind in ("v2ray", "clash", "singbox"):
        if kind in name:
            return kind
    return ""


# ---------------------------------------------------------------- 后处理：排序 + 策略组
# 越靠前的协议，在国内（尤其电信）越不容易被 DPI 识别阻断。
TYPE_RANK = {
    "vless": 0,
    "trojan": 1,
    "anytls": 2,
    "vmess": 3,
    "tuic": 4,
    "hysteria2": 5,
    "hysteria": 6,
    "ss": 8,
    "ssr": 9,
}
TLS_PORTS = {"8443", "2053", "2083", "2087", "2096", "2095"}
GROUP_AUTO = "🚀 自动选择"
GROUP_FALLBACK = "🔯 故障转移"
GROUP_MANUAL = "🎯 手动选择"


def decode_b64(text: str) -> str:
    body = text.strip().replace("\n", "").replace("\r", "")
    body = body.replace("-", "+").replace("_", "/")
    return base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "ignore")


def port_rank(port: object) -> int:
    value = str(port or "")
    if value == "443":
        return 0
    if value in TLS_PORTS:
        return 1
    return 2


def _ss_port(body: str) -> object:
    main = body.split("#", 1)[0].split("?", 1)[0]
    if "@" in main:
        hostport = main.rsplit("@", 1)[1]
    else:
        try:
            hostport = decode_b64(main).rsplit("@", 1)[-1]
        except Exception:  # noqa: BLE001
            return None
    return hostport.rsplit(":", 1)[1] if ":" in hostport else None


def parse_link(line: str) -> tuple[str, object]:
    """返回 (协议, 端口)，解析失败时端口为 None。"""
    if "://" not in line:
        return "", None
    scheme, body = line.split("://", 1)
    scheme = scheme.lower()
    if scheme == "vmess":
        try:
            return "vmess", json.loads(decode_b64(body)).get("port")
        except Exception:  # noqa: BLE001
            return "vmess", None
    if scheme == "ssr":
        try:
            parts = decode_b64(body.rsplit("/", 1)[0]).split(":")
            return "ssr", parts[1] if len(parts) > 1 else None
        except Exception:  # noqa: BLE001
            return "ssr", None
    if scheme == "ss":
        return "ss", _ss_port(body)
    try:
        return scheme, urllib.parse.urlsplit(line).port
    except Exception:  # noqa: BLE001
        return scheme, None


def link_key(line: str) -> tuple:
    kind, port = parse_link(line)
    return (TYPE_RANK.get(kind, 7), port_rank(port))


def build_clash(text: str, yaml) -> str:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return text
    proxies = [item for item in (data.get("proxies") or []) if isinstance(item, dict) and item.get("name")]
    if len(proxies) < 2:
        return text

    ranked = sorted(
        proxies,
        key=lambda item: (TYPE_RANK.get(str(item.get("type", "")).lower(), 7), port_rank(item.get("port"))),
    )
    names = [item["name"] for item in ranked]
    data["proxies"] = ranked
    data["proxy-groups"] = [
        {
            "name": GROUP_AUTO,
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": names,
        },
        {
            "name": GROUP_FALLBACK,
            "type": "fallback",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": names,
        },
        {"name": GROUP_MANUAL, "type": "select", "proxies": [GROUP_AUTO, GROUP_FALLBACK, "DIRECT"] + names},
    ]
    data["rules"] = ["GEOIP,CN,DIRECT", f"MATCH,{GROUP_AUTO}"]
    return yaml.dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False, width=10000)


def build_v2ray(text: str) -> str:
    raw = text.strip()
    decoded = ""
    try:
        decoded = decode_b64(raw)
    except Exception:  # noqa: BLE001
        decoded = ""
    if "://" not in decoded:
        decoded = text

    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if len(lines) < 2:
        return text
    ordered = sorted(lines, key=link_key)
    if ordered == lines:
        return text
    return base64.b64encode("\n".join(ordered).encode("utf-8")).decode("ascii")


def build_singbox(text: str) -> str:
    data = json.loads(text)
    outbounds = data.get("outbounds")
    if not isinstance(outbounds, list) or len(outbounds) < 2:
        return text

    skip = {"selector", "urltest", "direct", "block", "dns"}
    nodes, others = [], []
    for item in outbounds:
        if isinstance(item, dict) and item.get("type") not in skip:
            nodes.append(item)
        else:
            others.append(item)

    nodes.sort(key=lambda item: (TYPE_RANK.get(str(item.get("type", "")).lower(), 7), port_rank(item.get("server_port"))))
    data["outbounds"] = nodes + others
    return json.dumps(data, ensure_ascii=False, indent=2)


def cmd_postprocess() -> int:
    """把最可能在国内可用的节点排到前面，并给 Clash 订阅补上自动选择策略组。"""
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        yaml = None

    by_gist: dict[str, dict[str, str]] = {}
    for item in storage_items().values():
        filename = item.get("filename", "")
        kind = kind_of(filename)
        if not kind:
            continue
        gist_id = item["gist_id"]
        try:
            content = fetch_gist(gist_id).get(filename, "")
        except Exception as exc:  # noqa: BLE001
            print(f"[guard] 读取 {filename} 失败，跳过后处理：{exc}")
            continue
        if not content.strip():
            continue

        try:
            if kind == "clash" and yaml is not None:
                updated = build_clash(content, yaml)
            elif kind == "v2ray":
                updated = build_v2ray(content)
            elif kind == "singbox":
                updated = build_singbox(content)
            else:
                continue
        except Exception as exc:  # noqa: BLE001
            # 后处理失败不能影响主流程，保持原样即可
            print(f"[guard] 后处理 {filename} 失败，保持原样：{exc}")
            continue

        if updated != content:
            by_gist.setdefault(gist_id, {})[filename] = updated
            print(f"[guard] {filename} 已按协议/端口重排")
        else:
            print(f"[guard] {filename} 无需重排")

    for gist_id, payload in by_gist.items():
        if not payload:
            continue
        request(f"{API}/{gist_id}", method="PATCH", payload={"files": {k: {"content": v} for k, v in payload.items()}})
        print(f"[guard] 已写回 {gist_id}：{', '.join(payload)}")
    return 0


def count_by_kind(kind: str, content: str) -> int:
    if kind == "v2ray":
        return count_v2ray(content)
    if kind == "clash":
        return count_clash(content)
    if kind == "singbox":
        return count_singbox(content)
    return 1 if content.strip() else 0


def previous_counts() -> dict[str, int]:
    """上一次成功发布的节点数（来自本次运行前的备份）。"""
    prev: dict[str, int] = {}
    if not os.path.isdir(BACKUP_DIR):
        return prev
    for name in os.listdir(BACKUP_DIR):
        filename = name.split("__", 1)[-1]
        kind = kind_of(filename)
        if not kind:
            continue
        try:
            with open(os.path.join(BACKUP_DIR, name), encoding="utf-8") as fp:
                prev[kind] = max(prev.get(kind, 0), count_by_kind(kind, fp.read()))
        except OSError:
            continue
    return prev


def cmd_verify() -> int:
    failed = False
    prev = previous_counts()
    for key, item in storage_items().items():
        if key.startswith("crawled") or key == "pluginstate":
            continue
        gist_id, filename = item["gist_id"], item.get("filename", "")
        kind = kind_of(filename)
        if not kind:
            continue
        try:
            content = fetch_gist(gist_id).get(filename, "")
        except Exception as exc:  # noqa: BLE001
            print(f"[guard] 读取 {filename} 失败：{exc}")
            failed = True
            continue
        count = count_by_kind(kind, content)
        old = prev.get(kind, 0)
        limit = max(THRESHOLD[kind], int(old * 0.4))
        print(f"[guard] {filename}: {count} 个节点（上次 {old}，下限 {limit}），{len(content)} 字节")
        if count < limit:
            failed = True
    if failed:
        print("[guard] 校验未通过，将回滚到上一次结果")
        return 1
    print("[guard] 校验通过")
    return 0


def cmd_restore() -> int:
    if not os.path.isdir(BACKUP_DIR):
        print("[guard] 没有可用的备份，Gist 保持原样")
        return 0
    restored = 0
    for gist_id in {item["gist_id"] for item in storage_items().values()}:
        payload_files = {}
        prefix = f"{gist_id}__"
        for name in os.listdir(BACKUP_DIR):
            if not name.startswith(prefix):
                continue
            filename = name[len(prefix) :]
            with open(os.path.join(BACKUP_DIR, name), "r", encoding="utf-8") as fp:
                payload_files[filename] = {"content": fp.read()}
        if not payload_files:
            continue
        try:
            request(f"{API}/{gist_id}", method="PATCH", payload={"files": payload_files})
            restored += len(payload_files)
            print(f"[guard] 已回滚 {gist_id}: {', '.join(payload_files)}")
        except Exception as exc:  # noqa: BLE001
            print(f"[guard] 回滚 {gist_id} 失败：{exc}")
    print(f"[guard] 回滚完成，文件数：{restored}")
    return 0


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    handlers = {
        "backup": cmd_backup,
        "normalize": cmd_normalize,
        "postprocess": cmd_postprocess,
        "verify": cmd_verify,
        "restore": cmd_restore,
    }
    if action not in handlers:
        print(__doc__)
        return 2
    return handlers[action]()


if __name__ == "__main__":
    sys.exit(main())
