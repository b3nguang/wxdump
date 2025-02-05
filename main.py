# -*- coding: utf-8 -*-
"""
@ Author: b3nguang
@ Date: 2025-02-06 00:40:59
@ Description: WeChat Database Decryption and Message Export Tool
"""

import argparse
import ctypes
import hashlib
import hmac
import logging
import os
import shutil
import sqlite3
import sys
import winreg
from dataclasses import dataclass
from pathlib import Path

import psutil
import pymem
from Crypto.Cipher import AES

# Constants
KEY_SIZE = 32
DEFAULT_ITER = 64000
DEFAULT_PAGESIZE = 4096
SQLITE_FILE_HEADER = b"SQLite format 3\x00"
WIN_MAX_PATH = 260
USER_SPACE_LIMIT_64 = 0x7FFFFFFF0000
USER_SPACE_LIMIT_32 = 0x7FFF0000

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("wx_decrypt.log", encoding="utf-8")],
)
logger = logging.getLogger(__name__)


@dataclass
class WeChatInfo:
    """Data class to store WeChat process information"""

    pid: int
    wxid: str
    file_path: str
    key: str


class WeChatDecryptError(Exception):
    """Custom exception for WeChat decryption errors"""

    pass


# 获取exe文件的位数
def get_exe_bit(file_path):
    """
    获取 PE 文件的位数: 32 位或 64 位
    :param file_path:  PE 文件路径(可执行文件)
    :return: 如果遇到错误则返回 64
    """
    try:
        with open(file_path, "rb") as f:
            dos_header = f.read(2)
            if dos_header != b"MZ":
                logger.error("get exe bit error: Invalid PE file")
                return 64
            # Seek to the offset of the PE signature
            f.seek(60)
            pe_offset_bytes = f.read(4)
            pe_offset = int.from_bytes(pe_offset_bytes, byteorder="little")

            # Seek to the Machine field in the PE header
            f.seek(pe_offset + 4)
            machine_bytes = f.read(2)
            machine = int.from_bytes(machine_bytes, byteorder="little")

            if machine == 0x14C:
                return 32
            elif machine == 0x8664:
                return 64
            else:
                logger.error("get exe bit error: Unknown architecture: %s" % hex(machine))
                return 64
    except OSError:
        logger.error("get exe bit error: File not found or cannot be opened")
        return 64


def pattern_scan_all(handle, pattern, *, return_multiple=False, find_num=100):
    next_region = 0
    found = []
    user_space_limit = USER_SPACE_LIMIT_64 if sys.maxsize > 2**32 else USER_SPACE_LIMIT_32
    while next_region < user_space_limit:
        try:
            next_region, page_found = pymem.pattern.scan_pattern_page(handle, next_region, pattern, return_multiple=return_multiple)
        except Exception as e:
            logger.error(e)
            break
        if not return_multiple and page_found:
            return page_found
        if page_found:
            found += page_found
        if len(found) > find_num:
            break
    return found


def get_info_wxid(h_process):
    find_num = 100
    addrs = pattern_scan_all(h_process, rb"\\Msg\\FTSContact", return_multiple=True, find_num=find_num)
    wxids = []
    for addr in addrs:
        array = ctypes.create_string_buffer(80)
        if ctypes.windll.kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(addr - 30), array, 80, 0) == 0:
            return "None"
        array = bytes(array)  # .split(b"\\")[0]
        array = array.split(b"\\Msg")[0]
        array = array.split(b"\\")[-1]
        wxids.append(array.decode("utf-8", errors="ignore"))
    wxid = max(wxids, key=wxids.count) if wxids else "None"
    return wxid


def get_info_filePath_base_wxid(h_process, wxid=""):
    find_num = 10
    addrs = pattern_scan_all(h_process, wxid.encode() + rb"\\Msg\\FTSContact", return_multiple=True, find_num=find_num)
    filePath = []
    for addr in addrs:
        win_addr_len = WIN_MAX_PATH
        array = ctypes.create_string_buffer(win_addr_len)
        if ctypes.windll.kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(addr - win_addr_len + 50), array, win_addr_len, 0) == 0:
            return "None"
        array = bytes(array).split(b"\\Msg")[0]
        array = array.split(b"\00")[-1]
        filePath.append(array.decode("utf-8", errors="ignore"))
    filePath = max(filePath, key=filePath.count) if filePath else "None"
    return filePath


def get_info_filePath(wxid="all"):
    if not wxid:
        return "None"
    w_dir = "MyDocument:"
    is_w_dir = False

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\WeChat", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "FileSavePath")
        winreg.CloseKey(key)
        w_dir = value
        is_w_dir = True
    except Exception:
        w_dir = "MyDocument:"

    if not is_w_dir:
        try:
            user_profile = os.environ.get("USERPROFILE")
            path_3ebffe94 = os.path.join(user_profile, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config", "3ebffe94.ini")
            with open(path_3ebffe94, encoding="utf-8") as f:
                w_dir = f.read()
            is_w_dir = True
        except Exception:
            w_dir = "MyDocument:"

    if w_dir == "MyDocument:":
        try:
            # 打开注册表路径
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            documents_path = winreg.QueryValueEx(key, "Personal")[0]  # 读取文档实际目录路径
            winreg.CloseKey(key)  # 关闭注册表
            documents_paths = os.path.split(documents_path)
            if "%" in documents_paths[0]:
                w_dir = os.environ.get(documents_paths[0].replace("%", ""))
                w_dir = os.path.join(w_dir, os.path.join(*documents_paths[1:]))
                # print(1, w_dir)
            else:
                w_dir = documents_path
        except Exception:
            profile = os.environ.get("USERPROFILE")
            w_dir = os.path.join(profile, "Documents")

    msg_dir = os.path.join(w_dir, "WeChat Files")

    if wxid == "all" and os.path.exists(msg_dir):
        return msg_dir

    filePath = os.path.join(msg_dir, wxid)
    return filePath if os.path.exists(filePath) else "None"


def get_key(pid, db_path, addr_len):
    def read_key_bytes(h_process, address, address_len=8):
        array = ctypes.create_string_buffer(address_len)
        if ctypes.windll.kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address), array, address_len, 0) == 0:
            return "None"
        address = int.from_bytes(array, byteorder="little")  # 逆序转换为int地址（key地址）
        key = ctypes.create_string_buffer(32)
        if ctypes.windll.kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address), key, 32, 0) == 0:
            return "None"
        key_bytes = bytes(key)
        return key_bytes

    def verify_key(key, wx_db_path):
        with open(wx_db_path, "rb") as file:
            blist = file.read(5000)
        salt = blist[:16]
        byteKey = hashlib.pbkdf2_hmac("sha1", key, salt, DEFAULT_ITER, KEY_SIZE)
        first = blist[16:DEFAULT_PAGESIZE]

        mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
        mac_key = hashlib.pbkdf2_hmac("sha1", byteKey, mac_salt, 2, KEY_SIZE)
        hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
        hash_mac.update(b"\x01\x00\x00\x00")
        if hash_mac.digest() != first[-32:-12]:
            return False
        return True

    phone_type1 = "iphone\x00"
    phone_type2 = "android\x00"
    phone_type3 = "ipad\x00"

    pm = pymem.Pymem(pid)
    module_name = "WeChatWin.dll"

    MicroMsg_path = os.path.join(db_path, "MSG", "MicroMsg.db")

    type1_addrs = pm.pattern_scan_module(phone_type1.encode(), module_name, return_multiple=True)
    type2_addrs = pm.pattern_scan_module(phone_type2.encode(), module_name, return_multiple=True)
    type3_addrs = pm.pattern_scan_module(phone_type3.encode(), module_name, return_multiple=True)

    type_addrs = []
    if len(type1_addrs) >= 2:
        type_addrs += type1_addrs
    if len(type2_addrs) >= 2:
        type_addrs += type2_addrs
    if len(type3_addrs) >= 2:
        type_addrs += type3_addrs
    if len(type_addrs) == 0:
        return "None"

    type_addrs.sort()  # 从小到大排序

    for i in type_addrs[::-1]:
        for j in range(i, i - 2000, -addr_len):
            key_bytes = read_key_bytes(pm.process_handle, j, addr_len)
            if key_bytes == "None":
                continue
            if verify_key(key_bytes, MicroMsg_path):
                return key_bytes.hex()
    return "None"


# 读取微信信息(account,mobile,name,mail,wxid,key)
def read_info(is_logging=False, is_save=False):
    wechat_process = []
    result = []
    for process in psutil.process_iter(["name", "exe", "pid", "cmdline"]):
        if process.name() == "WeChat.exe":
            wechat_process.append(process)

    if len(wechat_process) == 0:
        error = "[-] WeChat No Run"
        if is_logging:
            logger.error(error)
        return error

    for process in wechat_process:
        tmp_rd = WeChatInfo(pid=process.pid, wxid="", file_path="", key="")

        Handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, process.pid)

        addrLen = get_exe_bit(process.exe()) // 8

        tmp_rd.wxid = get_info_wxid(Handle)
        tmp_rd.file_path = get_info_filePath_base_wxid(Handle, tmp_rd.wxid) if tmp_rd.wxid != "None" else "None"
        tmp_rd.file_path = get_info_filePath(tmp_rd.wxid) if tmp_rd.wxid != "None" and tmp_rd.file_path == "None" else tmp_rd.file_path
        tmp_rd.key = get_key(tmp_rd.pid, tmp_rd.file_path, addrLen) if tmp_rd.file_path != "None" else "None"
        result.append(tmp_rd)

    if is_logging:
        logger.info("=" * 32)
        if isinstance(result, str):  # 输出报错
            logger.error(result)
        else:  # 输出结果
            for _, rlt in enumerate(result):
                for k, v in rlt.__dict__.items():
                    logger.info(f"[+] {k:>8}: {v}")
                logger.info("-" * 32)
        logger.info("=" * 32)

    if is_save:
        with open("wx_info.txt", "w", encoding="utf-8") as f:
            f.write(str(result))
    return result


def get_wechat_processes() -> list[psutil.Process]:
    """获取所有运行中的微信进程

    Returns:
        List[psutil.Process]: 微信进程列表
    """
    return [proc for proc in psutil.process_iter(["name", "exe", "pid"]) if proc.name() == "WeChat.exe"]


def decrypt_message(path: str, password: bytes) -> None:
    """解密微信数据库文件

    Args:
        path: 数据库文件路径
        password: 解密密钥

    Raises:
        WeChatDecryptError: 解密失败时抛出
    """
    try:
        with open(path, "rb") as f:
            data = f.read()

        salt = data[:16]
        key = hashlib.pbkdf2_hmac("sha1", password, salt, DEFAULT_ITER, KEY_SIZE)
        page1 = data[16:DEFAULT_PAGESIZE]

        # 验证密码
        mac_salt = bytes([x ^ 0x3A for x in salt])
        mac_key = hashlib.pbkdf2_hmac("sha1", key, mac_salt, 2, KEY_SIZE)
        hash_mac = hmac.new(mac_key, digestmod="sha1")
        hash_mac.update(page1[:-32])
        hash_mac.update(bytes(ctypes.c_int(1)))

        if hash_mac.digest() != page1[-32:-12]:
            raise WeChatDecryptError("解密密钥错误")

        # 解密数据页
        pages = [data[i : i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(data), DEFAULT_PAGESIZE)]
        pages.insert(0, page1)

        with open(f"{path}.dec.db", "wb") as f:
            f.write(SQLITE_FILE_HEADER)
            for page in pages:
                cipher = AES.new(key, AES.MODE_CBC, page[-48:-32])
                f.write(cipher.decrypt(page[:-48]))
                f.write(page[-48:])

    except OSError as e:
        raise WeChatDecryptError(f"文件操作失败: {e}")
    except Exception as e:
        raise WeChatDecryptError(f"解密过程出错: {e}")


def query_database(db_path: str, query: str) -> list[tuple]:
    """执行数据库查询

    Args:
        db_path: 数据库文件路径
        query: SQL查询语句

    Returns:
        List[Tuple]: 查询结果行列表

    Raises:
        sqlite3.Error: 数据库操作错误
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    finally:
        conn.close()


def export_messages(msg_list: list[tuple[int, str]], nickname: str) -> None:
    """导出聊天记录到文件

    Args:
        msg_list: 消息列表，每个元组包含(是否发送者, 消息内容)
        nickname: 聊天对象昵称
    """
    logger.info(f"导出{nickname}的聊天记录...")
    output_file = Path(f"{nickname}.txt")

    with output_file.open("w", encoding="utf-8") as f:
        for is_sender, content in msg_list:
            msg_type = "发送" if is_sender == 1 else "接收"
            message = f"{msg_type}:{content}\n"
            f.write(message)
            logger.info(message.rstrip())

    logger.info(f"聊天记录已保存到 {output_file.absolute()}")


def get_messages(nickname: str, contact_db: str, msg_db: str) -> int:
    """获取指定用户的聊天记录

    Args:
        nickname: 用户昵称
        contact_db: 联系人数据库路径
        msg_db: 消息数据库路径

    Returns:
        int: 状态码 (1:成功, 2:用户不存在, 3:无聊天记录)
    """
    # 获取微信ID
    wxid_results = query_database(contact_db, f"SELECT UserName FROM Contact WHERE NickName='{nickname}'")

    if not wxid_results:
        logger.error(f"找不到用户: {nickname}")
        return 2

    wxid = wxid_results[0][0]

    # 获取聊天记录
    messages = query_database(msg_db, f"SELECT IsSender,StrContent FROM MSG WHERE StrTalker='{wxid}'")

    if not messages:
        logger.error(f"没有与 {nickname} 的聊天记录")
        return 3

    export_messages(messages, nickname)
    return 1


def safe_copy(src_path: str) -> str | None:
    """安全地复制文件到当前目录

    Args:
        src_path: 源文件路径

    Returns:
        Optional[str]: 目标文件路径，失败时返回None
    """
    try:
        current_dir = Path(__file__).parent
        dest_path = current_dir / Path(src_path).name
        shutil.copy(src_path, dest_path)
        return str(dest_path)
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.error(f"复制文件失败: {e}")
        return None


def main(nickname: str, use_decrypted: bool = False) -> None:
    """主函数

    Args:
        nickname: 要查询的用户昵称
        use_decrypted: 是否使用已解密的数据库
    """
    try:
        if not use_decrypted:
            # 获取微信信息
            wechat_info = read_info(is_logging=True, is_save=True)
            if isinstance(wechat_info, str):
                logger.error(wechat_info)
                return

            if not wechat_info:
                logger.error("未能获取微信进程信息")
                return

            info = wechat_info[0]
            key = bytes.fromhex(info.key)
            base_path = info.file_path

            # 复制并解密数据库
            contact_db = Path(base_path) / "Msg" / "MicroMsg.db"
            msg_db = Path(base_path) / "Msg" / "Multi" / "Msg0.db"

            contact_db_copy = safe_copy(str(contact_db))
            msg_db_copy = safe_copy(str(msg_db))

            if not all([contact_db_copy, msg_db_copy]):
                return

            decrypt_message(contact_db_copy, key)
            decrypt_message(msg_db_copy, key)
        else:
            current_dir = Path(__file__).parent
            contact_db_copy = str(current_dir / "MicroMsg.db")
            msg_db_copy = str(current_dir / "Msg0.db")

        # 获取并导出消息
        result = get_messages(nickname, f"{contact_db_copy}.dec.db", f"{msg_db_copy}.dec.db")

        if result != 1:
            return

    except WeChatDecryptError as e:
        logger.error(f"解密失败: {e}")
    except Exception as e:
        logger.error(f"处理过程出错: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="微信聊天记录导出工具")
    parser.add_argument("-n", "--nickname", required=True, help="要查询的用户昵称")
    parser.add_argument("-d", "--use-decrypted", action="store_true", help="使用已解密的数据库")

    args = parser.parse_args()
    main(args.nickname, args.use_decrypted)
