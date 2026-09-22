"""Dump COM vtable indices from SDK headers (order of declaration == vtable order).
Usage: python tools/dump_vtable.py d3d11 ID3D11DeviceContext
"""
import re
import sys

SDK_UM = r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um"
SDK_SHARED = r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"


def _read(header):
    for d in (SDK_UM, SDK_SHARED):
        try:
            with open(d + "\\" + header) as f:
                return f.read()
        except OSError:
            continue
    return ""


def methods(header, iface):
    t = _read(header)
    if not t:
        return []
    i = t.find("struct %sVtbl" % iface)
    if i < 0:
        return []
    seg = t[i:i + 25000]
    names = re.findall(r"\(\s*STDMETHODCALLTYPE\s*\*(\w+)\s*\)", seg)
    if len(names) < 5:
        names = re.findall(r"virtual \w+ STDMETHODCALLTYPE (\w+)\(", seg)
    return names


if __name__ == "__main__":
    header, iface = sys.argv[1], sys.argv[2]
    for n, m in enumerate(methods(header, iface)):
        print(n, m)
