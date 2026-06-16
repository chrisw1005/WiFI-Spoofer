import os
import sys
import subprocess
import tempfile

NPCAP_DOWNLOAD_URL = "https://npcap.com/dist/npcap-1.80.exe"


def check_npcap() -> None:
    """檢查 Windows 是否已安裝 Npcap，未安裝則提示下載安裝。"""
    if sys.platform != "win32":
        return

    npcap_dir = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "Npcap")
    if os.path.isdir(npcap_dir):
        return

    print("[!] 偵測到尚未安裝 Npcap（封包擷取驅動）。")
    print("[*] wifi-cut 需要 Npcap 才能執行網路掃描與 ARP 操作。\n")

    try:
        answer = input("是否自動下載並安裝 Npcap？(Y/n) ").strip().lower()
    except EOFError:
        answer = "y"

    if answer in ("", "y", "yes"):
        _download_and_install_npcap()
    else:
        print("[!] 請手動從 https://npcap.com 下載安裝 Npcap 後再執行本工具。")
        sys.exit(1)


def _download_and_install_npcap() -> None:
    """下載 Npcap 安裝程式並執行。"""
    import urllib.request

    installer_path = os.path.join(tempfile.gettempdir(), "npcap-setup.exe")
    print(f"[*] 正在下載 Npcap 安裝程式...")
    print(f"    URL: {NPCAP_DOWNLOAD_URL}")

    try:
        urllib.request.urlretrieve(NPCAP_DOWNLOAD_URL, installer_path)
    except Exception as e:
        print(f"[!] 下載失敗: {e}")
        print("[!] 請手動從 https://npcap.com 下載安裝。")
        sys.exit(1)

    print("[*] 正在啟動 Npcap 安裝程式...")
    print("[*] 請在彈出的安裝視窗中完成安裝（建議保留預設選項）。\n")

    try:
        result = subprocess.run([installer_path], check=False)
        if result.returncode != 0:
            print(f"[!] 安裝程式回傳錯誤碼: {result.returncode}")
            sys.exit(1)
    except Exception as e:
        print(f"[!] 無法執行安裝程式: {e}")
        sys.exit(1)

    npcap_dir = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "Npcap")
    if os.path.isdir(npcap_dir):
        print("[+] Npcap 安裝成功！\n")
    else:
        print("[!] 安裝似乎未完成，請手動安裝 Npcap 後再試。")
        sys.exit(1)

    try:
        os.remove(installer_path)
    except OSError:
        pass


def is_admin() -> bool:
    """是否具備系統管理員 / root 權限（不會結束程式，純查詢）。"""
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def check_root() -> None:
    if is_admin():
        return
    if sys.platform == "win32":
        print("[!] 此工具需要系統管理員權限，請以「以系統管理員身分執行」開啟終端。")
    else:
        print("[!] 此工具需要 root 權限，請使用 sudo 執行。")
    sys.exit(1)


def check_platform() -> None:
    if sys.platform not in ("darwin", "win32"):
        print("[!] 警告：此工具僅支援 macOS 和 Windows，其他平台可能不相容。")
    check_npcap()


def get_ip_forwarding() -> bool:
    if sys.platform == "win32":
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "global"],
            capture_output=True, text=True
        )
        return "forwarding" in result.stdout.lower() and "enabled" in result.stdout.lower()
    else:
        result = subprocess.run(
            ["sysctl", "-n", "net.inet.ip.forwarding"],
            capture_output=True, text=True
        )
        return result.stdout.strip() == "1"


def set_ip_forwarding(enable: bool) -> None:
    if sys.platform == "win32":
        val = "enabled" if enable else "disabled"
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "global", f"forwarding={val}"],
            capture_output=True, check=True
        )
    else:
        val = "1" if enable else "0"
        subprocess.run(
            ["sysctl", "-w", f"net.inet.ip.forwarding={val}"],
            capture_output=True, check=True
        )


def ensure_ip_forwarding_disabled() -> bool:
    """關閉 IP forwarding，回傳原始值以便之後還原。"""
    original = get_ip_forwarding()
    if original:
        set_ip_forwarding(False)
    return original


def ensure_ip_forwarding_enabled() -> bool:
    """開啟 IP forwarding，回傳原始值以便之後還原。"""
    original = get_ip_forwarding()
    if not original:
        set_ip_forwarding(True)
    return original
