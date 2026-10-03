"""Read-only Windows capability, file identity and NTFS journal APIs.

No volume access or hardware probing happens at import time.
"""
import ctypes
import json
import os
import shutil
import struct
import subprocess
from contextlib import contextmanager
from ctypes import wintypes
from functools import lru_cache


@lru_cache(maxsize=1)
def kernel():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    return k


def long_path(path):
    path = os.path.abspath(path)
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    return "\\\\?\\UNC\\" + path[2:] if path.startswith("\\\\") else "\\\\?\\" + path


@contextmanager
def handle(path, access=0, flags=0x02000000 | 0x00200000):
    k = kernel()
    h = k.CreateFileW(path, access, 7, None, 3, flags, None)
    if h == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield k, h
    finally:
        k.CloseHandle(h)


def ioctl(k, h, code, data=b"", size=65536):
    output = ctypes.create_string_buffer(size)
    length = wintypes.DWORD()
    source = ctypes.create_string_buffer(data) if data else None
    if not k.DeviceIoControl(h, code, source, len(data), output, size, ctypes.byref(length), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return output.raw[:length.value]


def identity(path=None, fd=None, stat=None):
    if os.name != "nt":
        stat = stat or (os.fstat(fd) if fd is not None else os.stat(path, follow_symlinks=False))
        return str(stat.st_dev), f"{stat.st_ino:032x}"
    class Info(ctypes.Structure):
        _fields_ = [("serial", ctypes.c_ulonglong), ("file_id", ctypes.c_ubyte * 16)]
    def read(k, h):
        info = Info()
        if not k.GetFileInformationByHandleEx(h, 18, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return f"{info.serial:016x}", bytes(info.file_id)[::-1].hex()
    if fd is not None:
        import msvcrt
        return read(kernel(), msvcrt.get_osfhandle(fd))
    with handle(long_path(path)) as (k, h):
        return read(k, h)


def change_token(fd, stat):
    """Consistent open-handle metadata change time, including restored-mtime changes."""
    if os.name != "nt":
        return stat.st_ctime_ns
    import msvcrt
    class Basic(ctypes.Structure):
        _fields_ = [("created", ctypes.c_longlong), ("accessed", ctypes.c_longlong),
                    ("modified", ctypes.c_longlong), ("changed", ctypes.c_longlong),
                    ("attributes", wintypes.DWORD)]
    data = Basic()
    if kernel().GetFileInformationByHandleEx(msvcrt.get_osfhandle(fd), 0, ctypes.byref(data), ctypes.sizeof(data)):
        return data.changed
    return None  # Some remote/filesystem providers cannot supply this extra signal.


def file_usn(path):
    with handle(long_path(path)) as (k, h):
        data = ioctl(k, h, 0x000900eb, struct.pack("<HH", 2, 3))
    records = list(parse_records(data, prefix=False))
    if len(records) != 1:
        raise ValueError("Malformed per-file USN response")
    return records[0]["usn"]


def volume_info(path):
    absolute = os.path.abspath(path)
    if os.name != "nt":
        usage = shutil.disk_usage(absolute)
        return {"path": absolute, "label": "", "filesystem": "unknown", "serial": str(os.stat(absolute).st_dev),
                "total": usage.total, "free": usage.free, "storage": "unknown", "local": True}
    k = kernel()
    root_buffer = ctypes.create_unicode_buffer(32768)
    if not k.GetVolumePathNameW(wintypes.LPCWSTR(absolute), root_buffer, len(root_buffer)):
        raise ctypes.WinError(ctypes.get_last_error())
    root = root_buffer.value
    label, fs = ctypes.create_unicode_buffer(261), ctypes.create_unicode_buffer(261)
    serial, max_component, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    if not k.GetVolumeInformationW(wintypes.LPCWSTR(root), label, len(label), ctypes.byref(serial),
                                   ctypes.byref(max_component), ctypes.byref(flags), fs, len(fs)):
        raise ctypes.WinError(ctypes.get_last_error())
    usage = shutil.disk_usage(root)
    remote = k.GetDriveTypeW(wintypes.LPCWSTR(root)) == 4
    storage = "remote" if remote else "unknown"
    if not remote and len(root) == 3:
        try:
            with handle("\\\\.\\" + root[:2]) as (api, h):
                penalty = ioctl(api, h, 0x002d1400, struct.pack("<III", 7, 0, 0), 128)
                device = ioctl(api, h, 0x002d1400, struct.pack("<III", 0, 0, 0), 1024)
                if len(penalty) >= 9:
                    storage = "hdd" if penalty[8] else "ssd"
                if len(device) >= 32 and struct.unpack_from("<I", device, 28)[0] == 17:
                    storage = "nvme"
        except OSError:
            pass  # Capability unavailable, conservative budget remains in effect.
    return {"path": root, "label": label.value, "filesystem": fs.value,
            "serial": f"{serial.value:08x}", "total": usage.total, "free": usage.free,
            "storage": storage, "local": not remote}


def drives():
    if os.name != "nt":
        return [volume_info(os.path.abspath(os.sep))]
    mask = kernel().GetLogicalDrives()
    result = []
    for i in range(26):
        if mask & (1 << i):
            path = chr(65 + i) + ":\\"
            try:
                result.append(volume_info(path))
            except OSError as exc:
                result.append({"path": path, "error": str(exc), "filesystem": "unavailable", "storage": "unknown"})
    return result


def journal(path):
    if os.name != "nt":
        raise OSError("USN requires Windows NTFS")
    info = volume_info(path)
    if info["filesystem"] != "NTFS" or not info["local"] or len(info["path"]) != 3:
        raise OSError("USN requires a local NTFS drive")
    with handle("\\\\.\\" + info["path"][:2], 0x80000000, 0) as (k, h):
        data = ioctl(k, h, 0x000900f4)
    if len(data) < 56:
        raise ValueError("Malformed journal response")
    jid, first, next_usn, lowest, maximum, max_size, delta = struct.unpack_from("<QqqqqQQ", data)
    return {"volume": info["path"], "serial": info["serial"], "journal_id": str(jid),
            "first_usn": first, "next_usn": next_usn, "lowest_valid_usn": lowest,
            "filesystem": info["filesystem"]}


def continuity(previous, current):
    if not previous:
        return False, "No previous journal checkpoint"
    if previous["serial"] != current["serial"]:
        return False, "Volume changed"
    if previous["journal_id"] != current["journal_id"]:
        return False, "Journal ID changed"
    checkpoint = previous["next_usn"]
    if checkpoint < max(current["first_usn"], current["lowest_valid_usn"]):
        return False, "Journal records rolled off"
    if checkpoint > current["next_usn"]:
        return False, "Journal moved backwards"
    return True, "Continuous"


def parse_records(data, prefix=True):
    offset = 8 if prefix else 0
    if len(data) < offset:
        raise ValueError("Truncated USN buffer")
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError("Truncated USN record")
        length, version = struct.unpack_from("<IH", data, offset)
        base = 60 if version == 2 else 76 if version == 3 else 0
        if not base or length < base or offset + length > len(data) or length % 8:
            raise ValueError("Unsupported or malformed USN record")
        width = 8 if version == 2 else 16
        file_id = int.from_bytes(data[offset + 8:offset + 8 + width], "little")
        usn = struct.unpack_from("<q", data, offset + 8 + 2 * width)[0]
        reason = struct.unpack_from("<I", data, offset + 24 + 2 * width)[0]
        name_len, name_offset = struct.unpack_from("<HH", data, offset + base - 4)
        if name_offset < base or name_offset + name_len > length or name_len % 2:
            raise ValueError("Malformed USN filename")
        yield {"file_id": f"{file_id:032x}", "usn": usn, "reason": reason}
        offset += length


def journal_changes(previous, current):
    valid, reason = continuity(previous, current)
    if not valid:
        raise ValueError(reason)
    checkpoint, end = previous["next_usn"], current["next_usn"]
    with handle("\\\\.\\" + current["volume"][:2], 0x80000000, 0) as (k, h):
        while checkpoint < end:
            request = struct.pack("<qIIQQQ", checkpoint, 0xffffffff, 0, 0, 0, int(current["journal_id"]))
            data = ioctl(k, h, 0x000900bb, request, 1024 * 1024)
            if len(data) < 8:
                raise ValueError("Truncated journal response")
            next_usn = struct.unpack_from("<q", data)[0]
            if next_usn <= checkpoint:
                raise ValueError("Journal reader made no progress")
            for record in parse_records(data):
                if record["usn"] < end:
                    yield record
            checkpoint = next_usn
    valid, reason = continuity(previous, journal(current["volume"]))
    if not valid:
        raise ValueError(reason)


def capabilities(include_gpu=True):
    import psutil
    from importlib.metadata import version
    data = {"cpu_logical": os.cpu_count(), "cpu_physical": psutil.cpu_count(logical=False),
            "ram_bytes": psutil.virtual_memory().total, "gpu": [],
            "blake3_version": version("blake3"), "blake3_simd": "optimized Rust backend; ISA not reported",
            "gpu_backend": "unavailable", "signing": "Ed25519", "timestamp": "not configured", "volumes": drives()}
    import platform
    data["cpu_name"] = platform.processor()
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                data["cpu_name"] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    if include_gpu and os.name == "nt":
        try:
            output = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=8, creationflags=0x08000000, check=True)
            gpu = json.loads(output.stdout) if output.stdout.strip() else []
            data["gpu"] = gpu if isinstance(gpu, list) else [gpu]
            for item in data["gpu"]:
                name = item.get("Name", "")
                item["vendor"] = ("NVIDIA" if "NVIDIA" in name.upper() else "AMD" if any(s in name.upper() for s in ("AMD", "RADEON")) else
                                  "Intel" if "INTEL" in name.upper() else "unknown")
                item["vram_note"] = "WMI AdapterRAM is a 32-bit reported value; may underreport VRAM above 4 GiB"
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            data["gpu_detection_error"] = str(exc)
    for volume in data["volumes"]:
        try:
            volume["usn"] = journal(volume["path"])
        except (OSError, ValueError) as exc:
            volume["usn_error"] = str(exc)
    return data
