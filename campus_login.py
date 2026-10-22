#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
校园网自动登录守护脚本（启明星智能体部 · 第二轮考核作品）

功能定位
--------
解决“开机、连上校园网后还要手动打开网页输账号密码，掉线后还得重登”这个
真实小问题。脚本常驻后台，周期性检测联网状态，一旦发现被认证网关挡住，就
自动调用认证接口登录，跑通“检测断网 -> 调用认证网关 -> 复核恢复在线”这条
完整闭环，全程无需人工干预。

用法
----
    python campus_login.py                 # 守护模式（默认，常驻后台循环检测）
    python campus_login.py --once          # 检测并登录一次后退出（用于测试）
    python campus_login.py --diag          # 输出环境/网络/配置诊断信息后退出
    python campus_login.py --verbose       # 守护模式同时打印日志到控制台（调试用）
    python campus_login.py --install       # 注册 Windows 开机自启（登录时后台启动）
    python campus_login.py --uninstall     # 移除开机自启

配置
----
账号密码、网关参数与运行参数统一放在与脚本同目录的 campus_login.ini 中
（见示例 campus_login.ini.example）。设备相关的 wlanuserip / mac / hostname
默认自动探测，也可在 ini 中固定覆盖。代码、示例与日志中不包含任何真实凭据。
"""

import argparse
import configparser
import logging
import os
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

import requests

# ===================== 常量与内置默认（可被 campus_login.ini 覆盖） =====================
CONFIG_FILE = "campus_login.ini"          # 配置文件名，和脚本同目录
LOG_FILE = "campus_login.log"             # 日志文件名，和脚本同目录
TASK_NAME = "CampusAutoLogin"             # Windows 计划任务名
SINGLE_INSTANCE_PORT = 47219              # 守护模式单实例互斥端口（仅监听本机）

DEFAULT_BASE_URL = "http://172.16.253.121/quickauth.do"

# 学校认证网关的“固定参数”（与具体设备无关，一般无需修改；可在 ini [gateway] 覆盖）
DEFAULT_GATEWAY_PARAMS = {
    "wlanacname": "NFV-BASE-SGYD",
    "wlanaclp": "172.16.253.113",
    "ssid": "",
    "vlan": "194",
    "version": "0",
    "portalpageid": "2",
    "portaltype": "0",
    "bindCtrlId": "",
    "validateType": "0",
    "bindOperatorType": "2",
    "sendFttrNotice": "0",
}
# 注意：wlanuserip / mac / hostname 与设备相关，不再硬编码，运行时自动探测
# （可在 ini [gateway] 中固定覆盖）。

# 联网探测：HTTP 的 generate_204 端点能识别“认证网关劫持”（在线返回 204，
# 被拦截时会返回 200/302 的认证页）；HTTPS 站点作为兜底（TLS 无法被静默劫持）。
PORTAL_204_SITES = [
    "http://connect.rom.miui.com/generate_204",
    "http://connectivitycheck.platform.hicloud.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
]
HTTPS_SITES = [
    "https://www.baidu.com",
    "https://www.qq.com",
    "https://www.aliyun.com",
]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Requested-With": "XMLHttpRequest",
}

# 运行参数内置默认（可在 ini [settings] 覆盖）
DEFAULT_SETTINGS = {
    "check_interval": 30,   # 网络检测间隔（秒）
    "login_timeout": 10,    # 登录请求超时（秒）
    "check_timeout": 3,     # 连通性检测单站点超时（秒）
    "max_retry": 3,         # 一轮登录最多尝试次数
    "retry_backoff": 5,     # 重试退避基数（秒），实际按 5 -> 10 -> 20 指数递增
    "log_level": "INFO",
}

# 网关返回“账号已在线”类提示时，往往意味着网络其实已经可用，做联网复核即可
ALREADY_ONLINE_HINTS = ("已经在线", "已在线", "不允许更多登陆", "不允许更多登录",
                        "EOVERCONCURRENCY", "OVERCONCURRENCY")
# 网关成功码（不同学校可能是字符串/数字，统一按字符串比对）
SUCCESS_CODES = {"0", "0000", "200", "success", "ok"}
# ==============================================================================

script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, CONFIG_FILE)
log_path = os.path.join(script_dir, LOG_FILE)

log = logging.getLogger("campus")


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
@dataclass
class Config:
    # 账号
    user_id: str = ""
    password: str = ""
    config_exists: bool = False
    # 网关
    base_url: str = DEFAULT_BASE_URL
    gateway_params: dict = field(default_factory=lambda: dict(DEFAULT_GATEWAY_PARAMS))
    wlanuserip: str = ""      # 留空 -> 自动探测本机出口 IP
    mac: str = ""             # 留空 -> 自动获取本机 MAC
    hostname: str = ""        # 留空 -> 自动获取本机主机名
    # 运行参数
    check_interval: int = DEFAULT_SETTINGS["check_interval"]
    login_timeout: int = DEFAULT_SETTINGS["login_timeout"]
    check_timeout: int = DEFAULT_SETTINGS["check_timeout"]
    max_retry: int = DEFAULT_SETTINGS["max_retry"]
    retry_backoff: int = DEFAULT_SETTINGS["retry_backoff"]
    log_level: str = DEFAULT_SETTINGS["log_level"]


def _get_int(cp: configparser.ConfigParser, section: str, key: str, default: int) -> int:
    """安全读取整数，配置非法时回退默认值，绝不让程序崩在配置上。"""
    try:
        return int(cp.get(section, key, fallback=str(default)).strip())
    except (ValueError, TypeError):
        log.warning("配置项 %s.%s 不是合法整数，已使用默认值 %s", section, key, default)
        return default


def load_config() -> Config:
    """读取 ini；文件不存在时返回内置默认（账号为空），由调用方决定是否报错。"""
    cfg = Config()
    if not os.path.exists(config_path):
        return cfg
    cfg.config_exists = True

    cp = configparser.ConfigParser()
    # utf-8-sig 兼容 Windows 记事本“另存为 UTF-8”时自动加的 BOM，
    # 否则首个 [account] 段名前会混入 \ufeff，导致读不到账号、误报“账号为空”
    cp.read(config_path, encoding="utf-8-sig")

    # 账号
    cfg.user_id = cp.get("account", "user_id", fallback="").strip()
    cfg.password = cp.get("account", "password", fallback="").strip()

    # 网关
    cfg.base_url = cp.get("gateway", "base_url", fallback=DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
    cfg.wlanuserip = cp.get("gateway", "wlanuserip", fallback="").strip()
    cfg.mac = cp.get("gateway", "mac", fallback="").strip()
    cfg.hostname = cp.get("gateway", "hostname", fallback="").strip()
    if cp.has_section("gateway"):
        for key in DEFAULT_GATEWAY_PARAMS:
            if cp.has_option("gateway", key):
                val = cp.get("gateway", key).strip()
                if val:
                    cfg.gateway_params[key] = val

    # 运行参数
    cfg.check_interval = _get_int(cp, "settings", "check_interval", cfg.check_interval)
    cfg.login_timeout = _get_int(cp, "settings", "login_timeout", cfg.login_timeout)
    cfg.check_timeout = _get_int(cp, "settings", "check_timeout", cfg.check_timeout)
    cfg.max_retry = _get_int(cp, "settings", "max_retry", cfg.max_retry)
    cfg.retry_backoff = _get_int(cp, "settings", "retry_backoff", cfg.retry_backoff)
    cfg.log_level = cp.get("settings", "log_level", fallback=cfg.log_level).strip().upper() or cfg.log_level
    return cfg


# ---------------------------------------------------------------------------
# 日志：轮转文件 + 可选控制台；绝不记录带密码的完整 URL
# ---------------------------------------------------------------------------
def setup_logging(console: bool = False, level: str = "INFO"):
    file_handler = RotatingFileHandler(
        log_path, maxBytes=1 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handlers = [file_handler]
    if console:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
        force=True,
    )


# ---------------------------------------------------------------------------
# 设备信息自动探测
# ---------------------------------------------------------------------------
def detect_local_ip(peer_host: str) -> str:
    """
    用 UDP “假连接”取得本机访问网关时使用的出口 IP（不会真正发包）。
    连不上网关时退而求其次连公共 DNS 取路由选择的内网 IP。
    """
    for peer in (peer_host, "223.5.5.5"):
        if not peer:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((peer, 80))
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    return ""


def detect_mac() -> str:
    """获取本机 MAC 并格式化为冒号分隔的 6 段小写形式。"""
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -8, -8))


def gateway_host(cfg: Config) -> str:
    try:
        return urlparse(cfg.base_url).hostname or ""
    except Exception:
        return ""


def build_auth_params(cfg: Config) -> dict:
    """每次登录前重新构造参数，确保 IP/主机名是最新的（应对“IP会话不存在”）。"""
    params = dict(cfg.gateway_params)
    params.update({
        "wlanuserip": cfg.wlanuserip or detect_local_ip(gateway_host(cfg)),
        "hostname": cfg.hostname or socket.gethostname(),
        "mac": cfg.mac or detect_mac(),
        "userid": cfg.user_id,
        "passwd": cfg.password,
        "timestamp": str(int(time.time() * 1000)),
        "uuid": str(uuid.uuid4()),
    })
    return params


# ---------------------------------------------------------------------------
# 联网检测：204 探测为主、HTTPS 兜底，任一确认在线即视为在线
# ---------------------------------------------------------------------------
def is_online(cfg: Config) -> bool:
    # 1) HTTP generate_204：在线严格返回 204；connecttest.txt 在线返回固定文本
    for site in PORTAL_204_SITES:
        try:
            resp = requests.get(site, timeout=cfg.check_timeout, allow_redirects=False)
            if resp.status_code == 204:
                return True
            if resp.status_code == 200 and "Microsoft Connect Test" in resp.text:
                return True
            # 200/302 但内容是认证页 -> 被网关劫持，判离线，继续探测
        except requests.RequestException:
            continue
    # 2) HTTPS 兜底：认证网关无法对 https 静默劫持（证书不匹配会直接报错），
    #    能正常完成请求即说明真正联网
    for site in HTTPS_SITES:
        try:
            requests.get(site, timeout=cfg.check_timeout)
            return True
        except requests.RequestException:
            continue
    return False


# ---------------------------------------------------------------------------
# 网关返回解析
# ---------------------------------------------------------------------------
def gateway_success(data: dict) -> bool:
    code = str(data.get("code", "")).strip().lower()
    if code in SUCCESS_CODES:
        return True
    return "成功" in str(data.get("message", ""))


def gateway_already_online(data: dict) -> bool:
    blob = f"{data.get('code', '')}{data.get('message', '')}"
    return any(hint in blob for hint in ALREADY_ONLINE_HINTS)


# ---------------------------------------------------------------------------
# 登录：全异常捕获 + 指数退避重试 + 联网复核，绝不抛出
# ---------------------------------------------------------------------------
def campus_login(cfg: Config) -> bool:
    """执行一轮登录（最多 max_retry 次），返回最终是否确认在线。"""
    for attempt in range(1, cfg.max_retry + 1):
        params = build_auth_params(cfg)
        try:
            resp = requests.get(cfg.base_url, params=params,
                                headers=HEADERS, timeout=cfg.login_timeout)
            try:
                data = resp.json()
            except ValueError:
                log.warning("认证网关返回非 JSON（HTTP %s，第 %d 次）",
                            resp.status_code, attempt)
            else:
                message = data.get("message", "无返回信息")
                if gateway_success(data):
                    log.info("网关返回成功：%s", message)
                    time.sleep(2)  # 给认证状态下发/路由刷新一点时间，再复核
                    if is_online(cfg):
                        log.info("联网复核通过，已恢复上网")
                        return True
                    log.warning("网关返回成功但联网复核未通过，会话可能仍在建立")
                elif gateway_already_online(data):
                    log.info("网关提示账号已在线：%s", message)
                    if is_online(cfg):
                        log.info("当前确已联网，无需重复登录")
                        return True
                else:
                    log.info("登录未成功：%s（第 %d 次）", message, attempt)
        except requests.RequestException as e:
            # 只记录异常类型名，requests 的异常文本会带含账号密码的完整 URL
            log.warning("登录请求异常（第 %d 次）：%s", attempt, type(e).__name__)
        except Exception as e:  # noqa: BLE001 - 守护进程任何异常都不能中断主循环
            log.warning("登录处理异常（第 %d 次）：%s", attempt, type(e).__name__)

        if attempt < cfg.max_retry:
            delay = cfg.retry_backoff * (2 ** (attempt - 1))  # 5s -> 10s -> 20s
            log.info("等待 %d 秒后重试（第 %d/%d 次）", delay, attempt, cfg.max_retry)
            time.sleep(delay)

    online = is_online(cfg)
    log.warning("本轮 %d 次尝试结束，最终复核：%s",
                cfg.max_retry, "已在线" if online else "仍离线")
    return online


# ---------------------------------------------------------------------------
# 开机自启（Windows 计划任务：用户登录时以无控制台窗口方式后台启动）
# ---------------------------------------------------------------------------
def _pythonw() -> str:
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        return exe[:-len("python.exe")] + "pythonw.exe"
    return exe


def install_startup():
    exe = _pythonw()
    if not os.path.exists(exe):
        exe = sys.executable  # 找不到 pythonw 时退回 python（会带控制台，仍可用）
    script = os.path.abspath(__file__)
    cmd = [
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", f'"{exe}" "{script}"',
        "/sc", "onlogon", "/rl", "highest", "/f",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"[OK] 已注册开机自启：任务名 {TASK_NAME}（登录 Windows 时后台运行）")
        print(f"     解释器：{exe}")
    except Exception as e:
        sys.exit(f"[错误] 注册开机自启失败：{type(e).__name__}，请以管理员身份重试。")


def uninstall_startup():
    cmd = ["schtasks", "/delete", "/tn", TASK_NAME, "/f"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"[OK] 已移除开机自启：任务名 {TASK_NAME}")
    except Exception as e:
        sys.exit(f"[错误] 移除开机自启失败：{type(e).__name__}（可能本就未注册）")


def startup_installed() -> bool:
    result = subprocess.run(
        ["schtasks", "/query", "/tn", TASK_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# 守护模式单实例：避免重复守护、重复登录
# ---------------------------------------------------------------------------
_single_sock = None


def acquire_single_instance() -> bool:
    global _single_sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", SINGLE_INSTANCE_PORT))
        sock.listen(1)
        _single_sock = sock  # 保持引用，避免被回收导致锁释放
        return True
    except OSError:
        sock.close()
        return False


# ---------------------------------------------------------------------------
# 诊断：便于排查环境问题（答辩也可现场演示）
# ---------------------------------------------------------------------------
def mask(text: str) -> str:
    if not text:
        return "（未配置）"
    return text[:2] + "***" + text[-2:] if len(text) > 4 else "***"


def show_diag(cfg: Config):
    host = gateway_host(cfg)
    print("============ 校园网自动登录 · 环境诊断 ============")
    print(f"脚本目录      : {script_dir}")
    print(f"Python 版本   : {sys.version.split()[0]}（{sys.executable}）")
    print(f"配置文件      : {config_path}  [{'存在' if cfg.config_exists else '不存在'}]")
    print(f"账号          : {mask(cfg.user_id)}")
    print(f"密码          : {'已配置' if cfg.password else '（未配置）'}")
    print(f"网关地址      : {cfg.base_url}")
    print(f"本机出口 IP   : {cfg.wlanuserip or detect_local_ip(host) or '（探测失败）'}")
    print(f"主机名        : {cfg.hostname or socket.gethostname()}")
    print(f"MAC           : {cfg.mac or detect_mac()}")
    print(f"开机自启      : {'已注册' if startup_installed() else '未注册'}")
    print(f"检测间隔/重试 : {cfg.check_interval}s / 最多 {cfg.max_retry} 次")
    print("正在检测联网状态（可能需要几秒）...")
    print(f"联网状态      : {'在线' if is_online(cfg) else '离线（被认证网关拦截）'}")
    print("==================================================")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run_once(cfg: Config) -> bool:
    """检测一次：在线则不重复登录，离线则登录，返回当前是否在线。"""
    if is_online(cfg):
        log.info("当前网络已在线，无需登录")
        return True
    log.info("检测到未在线，尝试登录")
    return campus_login(cfg)


def main():
    parser = argparse.ArgumentParser(description="校园网自动登录守护脚本")
    parser.add_argument("--once", action="store_true", help="检测并登录一次后退出")
    parser.add_argument("--diag", action="store_true", help="输出环境/网络/配置诊断后退出")
    parser.add_argument("--verbose", action="store_true", help="守护模式同时输出日志到控制台")
    parser.add_argument("--install", action="store_true", help="注册开机自启")
    parser.add_argument("--uninstall", action="store_true", help="移除开机自启")
    args = parser.parse_args()

    # 自启的注册/移除不需要初始化日志，但注册前必须确认账号已填好：
    # 否则开机时 pythonw 无窗口静默退出，用户看不到失败原因
    if args.install:
        cfg_pre = load_config()
        if not cfg_pre.config_exists or not cfg_pre.user_id or not cfg_pre.password:
            sys.exit(
                "[提示] 请先复制 campus_login.ini.example 为 campus_login.ini、填好账号密码，"
                "再注册开机自启，否则开机时会因缺少账号而静默启动失败。"
            )
        install_startup()
        return
    if args.uninstall:
        uninstall_startup()
        return

    cfg = load_config()
    setup_logging(console=(args.once or args.verbose or args.diag), level=cfg.log_level)

    if args.diag:
        show_diag(cfg)
        return

    # 守护/单次模式必须有账号
    if not cfg.config_exists:
        sys.exit(
            f"[错误] 未找到配置文件 {config_path}\n"
            f"      请复制 campus_login.ini.example 为 campus_login.ini 并填入账号密码。"
        )
    if not cfg.user_id or not cfg.password:
        sys.exit("[错误] campus_login.ini 中 [account] 的账号或密码为空，请填写后重试。")

    if args.once:
        run_once(cfg)
        return

    # 守护模式：单实例，避免重复运行
    if not acquire_single_instance():
        log.warning("已有一个守护实例在运行（端口 %s 被占用），本次退出。", SINGLE_INSTANCE_PORT)
        sys.exit("[提示] 已有一个守护实例在运行，无需重复启动。")

    log.info("程序启动，开始检测网络状态")
    run_once(cfg)

    while True:
        try:
            time.sleep(cfg.check_interval)
            if not is_online(cfg):
                log.info("检测到网络断开，尝试重新登录")
                campus_login(cfg)
        except Exception as e:  # noqa: BLE001 - 主循环永不因偶发异常退出
            log.error("主循环异常：%s", type(e).__name__)
            time.sleep(10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[已手动停止] 守护进程退出。")
    except SystemExit:
        raise
    except Exception as e:  # 顶层兜底，避免静默崩溃
        print(f"[错误] 程序异常退出：{type(e).__name__}: {e}")
        sys.exit(1)
