#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""国内本地筛选：只保留在你的网络里真正能连上的节点。

背景
----
GitHub Actions 的存活检测跑在海外机房，测的是「美国 -> 节点 -> Google」，
绕过了 GFW。所以订阅里 200+ 个「可用」节点，到上海电信手里大部分连不上。
这个脚本在你自己的电脑上跑，用你真实的网络做二次筛选。

用法
----
    python filter_cn.py                 # 只生成本地文件
    python filter_cn.py --push          # 额外推回 Gist（需要 GH_TOKEN 环境变量）
    python filter_cn.py --timeout 2 --workers 60

产出
----
    cn-v2ray.txt / cn-clash.yaml / cn-singbox.json   （当前目录）
    --push 时写到同一个 Gist，文件名同上，订阅地址见脚本结尾输出

说明
----
* 只测 TCP 握手，3 秒超时。TCP 都不通，代理一定不通；TCP 通了不代表协议可用
  （CDN 类节点尤其如此），所以这是「粗筛」，能干掉大部分死节点。
* hysteria2 / tuic 走 UDP，TCP 探测无意义，默认直接保留，不计入淘汰。
* 纯标准库，Windows / macOS / Linux 都能跑，不需要装任何依赖。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

GIST_USER = "zyqqai"
GIST_ID = "6dd682ceb71086a543387147fd4a0613"
RAW_BASE = f"https://gist.githubusercontent.com/{GIST_USER}/{GIST_ID}/raw"
UA = "Mozilla/5.0 (compatible; cn-filter/1.0)"

UDP_TYPES = {"hysteria2", "hysteria", "tuic"}
TYPE_RANK = {
    "vless": 0, "trojan": 1, "anytls": 2, "vmess": 3,
    "tuic": 4, "hysteria2": 5, "hysteria": 6, "ss": 8, "ssr": 9,
}
TLS_PORTS = {"8443", "2053", "2083", "2087", "2096", "2095"}


# ---------------------------------------------------------------- 基础工具
def http_get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


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


def sort_key(kind: str, port: object) -> tuple:
    return (TYPE_RANK.get(kind, 7), port_rank(port))


# ---------------------------------------------------------------- 链接解析
def _split_hostport(hostport: str) -> tuple[str, int] | None:
    hostport = hostport.strip().rstrip("/")
    if not hostport:
        return None
    if hostport.startswith("["):  # IPv6
        host, _, rest = hostport[1:].partition("]")
        port = rest.lstrip(":")
    elif ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    else:
        return None
    try:
        return host, int(port)
    except ValueError:
        return None


def parse_link(line: str) -> dict | None:
    """解析一行订阅链接，返回 {kind, host, port, raw}；失败返回 None。"""
    line = line.strip()
    if "://" not in line:
        return None
    scheme, body = line.split("://", 1)
    scheme = scheme.lower()

    if scheme == "vmess":
        try:
            info = json.loads(decode_b64(body))
            return {"kind": "vmess", "host": str(info.get("add", "")), "port": int(info.get("port", 0)), "raw": line}
        except Exception:
            return None

    if scheme == "ssr":
        try:
            parts = decode_b64(body.rsplit("/", 1)[0]).split(":")
            return {"kind": "ssr", "host": parts[0], "port": int(parts[1]), "raw": line}
        except Exception:
            return None

    if scheme == "ss":
        main = body.split("#", 1)[0].split("?", 1)[0]
        if "@" in main:
            hostport = main.rsplit("@", 1)[1]
        else:
            try:
                hostport = decode_b64(main).rsplit("@", 1)[-1]
            except Exception:
                return None
        hp = _split_hostport(hostport)
        return {"kind": "ss", "host": hp[0], "port": hp[1], "raw": line} if hp else None

    # vless / trojan / hysteria2 / tuic / anytls 等标准 URL 形式
    rest = body.split("#", 1)[0]
    if "@" not in rest:
        return None
    hostport = rest.rsplit("@", 1)[1].split("?", 1)[0].split("/", 1)[0]
    hp = _split_hostport(hostport)
    return {"kind": scheme, "host": hp[0], "port": hp[1], "raw": line} if hp else None


# ---------------------------------------------------------------- 三种格式的读写
def load_v2ray(text: str) -> list[dict]:
    raw = text.strip()
    decoded = ""
    try:
        decoded = decode_b64(raw)
    except Exception:
        decoded = ""
    if "://" not in decoded:
        decoded = text
    nodes = []
    for line in decoded.splitlines():
        item = parse_link(line)
        if item:
            nodes.append(item)
    return nodes


def load_clash(text: str, yaml) -> list[dict]:
    data = yaml.safe_load(text) or {}
    proxies = data.get("proxies") or [] if isinstance(data, dict) else data
    return [p for p in proxies if isinstance(p, dict) and p.get("server")]


def load_singbox(text: str) -> list[dict]:
    data = json.loads(text)
    skip = {"selector", "urltest", "direct", "block", "dns"}
    return [o for o in data.get("outbounds", []) if isinstance(o, dict) and o.get("type") not in skip]


# ---------------------------------------------------------------- TCP 探测
def tcp_alive(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def probe_all(targets: list[tuple[str, int]], timeout: float, workers: int) -> list[bool]:
    results: list[bool] = [False] * len(targets)
    done = ok = 0
    total = len(targets)
    step = max(1, total // 10)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(tcp_alive, h, p, timeout): i for i, (h, p) in enumerate(targets)}
        for fut, idx in futures.items():
            try:
                results[idx] = fut.result()
            except Exception:
                results[idx] = False
            if results[idx]:
                ok += 1
            done += 1
            if done % step == 0 or done == total:
                pct = done * 100 // total
                print(f"\r  探测进度 {done}/{total} ({pct}%)  已确认可用 {ok}", end="", flush=True)
    print()
    return results


# ---------------------------------------------------------------- 输出
def dump_v2ray(nodes: list[dict]) -> str:
    nodes = sorted(nodes, key=lambda n: sort_key(n["kind"], n["port"]))
    body = "\n".join(n["raw"] for n in nodes)
    return base64.b64encode(body.encode("utf-8")).decode("ascii")


def dump_clash(proxies: list[dict], yaml) -> str:
    ranked = sorted(proxies, key=lambda p: sort_key(str(p.get("type", "")).lower(), p.get("port")))
    names = [p["name"] for p in ranked]
    data = {
        "proxies": ranked,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "tolerance": 50, "proxies": names},
            {"name": "🔯 故障转移", "type": "fallback", "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
            {"name": "🎯 手动选择", "type": "select", "proxies": ["🚀 自动选择", "🔯 故障转移", "DIRECT"] + names},
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 自动选择"],
    }
    return yaml.dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False, width=10000)


def dump_singbox(outbounds: list[dict]) -> str:
    ranked = sorted(outbounds, key=lambda o: sort_key(str(o.get("type", "")).lower(), o.get("server_port")))
    return json.dumps({"outbounds": ranked}, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 推送
def push_gist(files: dict[str, str], token: str) -> None:
    payload = json.dumps({"files": {name: {"content": body} for name, body in files.items()}}).encode()
    req = urllib.request.Request(
        f"https://api.github.com/gists/{GIST_ID}",
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": UA,
        },
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp.read()
            print("[push] 已写回 Gist")
            return
        except urllib.error.HTTPError as exc:
            if exc.code in (409, 429, 500, 502, 503) and attempt < 2:
                time.sleep(3)
                continue
            raise
        except urllib.error.URLError:
            if attempt < 2:
                time.sleep(3)
                continue
            raise


# ---------------------------------------------------------------- 主流程
def main() -> int:
    parser = argparse.ArgumentParser(description="用你本地网络筛选可用节点")
    parser.add_argument("--timeout", type=float, default=3.0, help="TCP 超时秒数，默认 3")
    parser.add_argument("--workers", type=int, default=50, help="并发数，默认 50")
    parser.add_argument("--push", action="store_true", help="推回 Gist（需 GH_TOKEN）")
    parser.add_argument("--outdir", default=".", help="输出目录，默认当前目录")
    args = parser.parse_args()

    try:
        import yaml
    except ImportError:
        print("缺少 PyYAML，安装：pip install pyyaml")
        return 2

    print(f"拉取订阅：{RAW_BASE}")
    stamp = int(time.time())
    v2_text = http_get(f"{RAW_BASE}/free-v2ray.txt?t={stamp}")
    clash_text = http_get(f"{RAW_BASE}/free-clash.yaml?t={stamp}")
    sb_text = http_get(f"{RAW_BASE}/free-singbox.json?t={stamp}")

    v2_nodes = load_v2ray(v2_text)
    clash_nodes = load_clash(clash_text, yaml)
    sb_nodes = load_singbox(sb_text)
    print(f"解析到：v2ray {len(v2_nodes)} / clash {len(clash_nodes)} / singbox {len(sb_nodes)}")

    # 三类文件里的节点大体相同，用 host:port 合并成一张探测表，避免重复测
    endpoints: dict[tuple[str, int], list[bool]] = {}
    udp_skipped = set()
    for item in v2_nodes + [{"kind": p.get("type", ""), "host": p.get("server"), "port": p.get("port")} for p in clash_nodes] \
            + [{"kind": o.get("type", ""), "host": o.get("server"), "port": o.get("server_port")} for o in sb_nodes]:
        kind = str(item.get("kind", "")).lower()
        host, port = str(item.get("host") or ""), item.get("port")
        if not host or not port:
            continue
        try:
            key = (host, int(port))
        except (TypeError, ValueError):
            continue
        if kind in UDP_TYPES:
            udp_skipped.add(key)
        endpoints.setdefault(key, [])

    targets = [k for k in endpoints if k not in udp_skipped]
    print(f"待测 {len(targets)} 个 TCP 端点，UDP 协议（hysteria2/tuic）{len(udp_skipped)} 个直接保留")
    t0 = time.time()
    verdicts = probe_all(targets, args.timeout, args.workers)
    alive = {ep for ep, ok in zip(targets, verdicts) if ok} | udp_skipped
    print(f"探测完成，耗时 {time.time() - t0:.1f}s：可用 {len(alive)} / {len(endpoints)}")

    kept_v2 = [n for n in v2_nodes if (n["host"], n["port"]) in alive or str(n["kind"]).lower() in UDP_TYPES]
    kept_clash = [p for p in clash_nodes
                  if (str(p.get("server")), int(p.get("port") or 0)) in alive or str(p.get("type", "")).lower() in UDP_TYPES]
    kept_sb = [o for o in sb_nodes
               if (str(o.get("server")), int(o.get("server_port") or 0)) in alive or str(o.get("type", "")).lower() in UDP_TYPES]

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    files = {
        "cn-v2ray.txt": dump_v2ray(kept_v2),
        "cn-clash.yaml": dump_clash(kept_clash, yaml),
        "cn-singbox.json": dump_singbox(kept_sb),
    }
    for name, body in files.items():
        path = os.path.join(outdir, name)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(body if name != "cn-singbox.json" else body + "\n")
        print(f"  写入 {path}")

    if args.push:
        token = (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()
        if not token:
            print("[push] 未设置 GH_TOKEN，跳过推送")
        else:
            push_gist(files, token)
            print(f"[push] 订阅地址：{RAW_BASE}/cn-v2ray.txt")

    print("\n完成。可用节点数："
          f"v2ray {len(kept_v2)} / clash {len(kept_clash)} / singbox {len(kept_sb)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
