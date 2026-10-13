"""Decoding of OT protocol *commands* in captured payloads (no reassembly, one
packet at a time): what a client asked a controller to do, not just which
protocol was spoken.

- IEC 60870-5-104: control/setpoint commands, reset process, clock sync, file transfer
- DNP3: select/operate/direct operate, write, restarts, stop/start application, file ops
- S7comm: write var, PLC stop, PI service (start, insert/delete blocks), program
  download/upload, CPU password functions, SZL/block-list reconnaissance
- EtherNet/IP + CIP: tag writes, Set_Attribute, Reset/Start/Stop services,
  ListIdentity reconnaissance (Unconnected Send is unwrapped one level)

Each decoder returns a list of Command tuples. Categories:
control, write, program, stop, restart, config, file, auth, recon, time, other.
"""
from __future__ import annotations

import struct
from typing import NamedTuple


class Command(NamedTuple):
    protocol: str
    name: str
    category: str


# ------------------------------------------------------------------ IEC 104
IEC104_TYPES = {
    45: ("C_SC_NA_1 single command", "control"), 46: ("C_DC_NA_1 double command", "control"),
    47: ("C_RC_NA_1 regulating step", "control"), 48: ("C_SE_NA_1 setpoint normalized", "control"),
    49: ("C_SE_NB_1 setpoint scaled", "control"), 50: ("C_SE_NC_1 setpoint float", "control"),
    51: ("C_BO_NA_1 bitstring", "control"),
    58: ("C_SC_TA_1 single command (time tag)", "control"), 59: ("C_DC_TA_1 double command (time tag)", "control"),
    60: ("C_RC_TA_1 regulating step (time tag)", "control"), 61: ("C_SE_TA_1 setpoint normalized (time tag)", "control"),
    62: ("C_SE_TB_1 setpoint scaled (time tag)", "control"), 63: ("C_SE_TC_1 setpoint float (time tag)", "control"),
    64: ("C_BO_TA_1 bitstring (time tag)", "control"),
    100: ("C_IC_NA_1 interrogation", "recon"), 101: ("C_CI_NA_1 counter interrogation", "recon"),
    102: ("C_RD_NA_1 read", "recon"), 103: ("C_CS_NA_1 clock synchronization", "time"),
    104: ("C_TS_NA_1 test", "other"), 105: ("C_RP_NA_1 reset process", "restart"),
    106: ("C_CD_NA_1 delay acquisition", "time"), 107: ("C_TS_TA_1 test (time tag)", "other"),
    110: ("P_ME_NA_1 parameter normalized", "config"), 111: ("P_ME_NB_1 parameter scaled", "config"),
    112: ("P_ME_NC_1 parameter float", "config"), 113: ("P_AC_NA_1 parameter activation", "config"),
    120: ("F_FR_NA_1 file ready", "file"), 121: ("F_SR_NA_1 section ready", "file"),
    122: ("F_SC_NA_1 call/select file", "file"), 123: ("F_LS_NA_1 last section", "file"),
    124: ("F_AF_NA_1 ack file", "file"), 125: ("F_SG_NA_1 segment", "file"), 126: ("F_DR_TA_1 directory", "file"),
}
COT_ACTIVATION = 6


def iec104(payload: bytes, to_server: bool) -> list[Command]:
    """Commands in the control direction (client -> controlled station), activation COT."""
    out: list[Command] = []
    if not to_server:
        return out
    i = 0
    while i + 6 <= len(payload) and payload[i] == 0x68:
        ln = payload[i + 1]
        apdu = payload[i + 2:i + 2 + ln]
        if len(apdu) >= 4 + 3 and apdu[0] & 0x01 == 0:          # I-format with ASDU
            tid, cot = apdu[4], apdu[6] & 0x3F
            if tid in IEC104_TYPES and cot == COT_ACTIVATION:
                name, cat = IEC104_TYPES[tid]
                out.append(Command("IEC 104", name, cat))
        i += 2 + ln
    return out


# ------------------------------------------------------------------ DNP3
DNP3_FUNCS = {
    1: ("READ", "recon"), 2: ("WRITE", "write"), 3: ("SELECT", "control"), 4: ("OPERATE", "control"),
    5: ("DIRECT_OPERATE", "control"), 6: ("DIRECT_OPERATE_NR", "control"),
    7: ("IMMED_FREEZE", "other"), 8: ("IMMED_FREEZE_NR", "other"), 9: ("FREEZE_CLEAR", "write"),
    10: ("FREEZE_CLEAR_NR", "write"), 11: ("FREEZE_AT_TIME", "other"), 12: ("FREEZE_AT_TIME_NR", "other"),
    13: ("COLD_RESTART", "restart"), 14: ("WARM_RESTART", "restart"),
    15: ("INITIALIZE_DATA", "program"), 16: ("INITIALIZE_APPL", "program"), 17: ("START_APPL", "program"),
    18: ("STOP_APPL", "stop"), 19: ("SAVE_CONFIG", "config"), 20: ("ENABLE_UNSOLICITED", "config"),
    21: ("DISABLE_UNSOLICITED", "config"), 22: ("ASSIGN_CLASS", "config"), 23: ("DELAY_MEASURE", "time"),
    24: ("RECORD_CURRENT_TIME", "time"), 25: ("OPEN_FILE", "file"), 26: ("CLOSE_FILE", "file"),
    27: ("DELETE_FILE", "file"), 28: ("GET_FILE_INFO", "file"), 29: ("AUTHENTICATE_FILE", "file"),
    30: ("ABORT_FILE", "file"), 31: ("ACTIVATE_CONFIG", "config"),
    32: ("AUTHENTICATE_REQ", "auth"), 33: ("AUTH_REQ_NO_ACK", "auth"),
}


def dnp3(payload: bytes, to_server: bool) -> list[Command]:
    """First fragment of each link frame: transport header + application header.
    Requests (function codes 1-33) only; responses (129+) are ignored."""
    out: list[Command] = []
    i = 0
    while i + 13 <= len(payload) and payload[i] == 0x05 and payload[i + 1] == 0x64:
        ln = payload[i + 2]                       # bytes after the length field, excluding CRCs
        ctrl = payload[i + 3]
        user = ln - 5
        nblocks = (user + 15) // 16 if user > 0 else 0
        frame_len = 10 + user + 2 * nblocks
        if user > 0 and ctrl & 0x40:              # primary frame with user data
            transport = payload[i + 10]
            if transport & 0x40 and i + 12 < len(payload):     # FIR: first segment
                fc = payload[i + 12]
                if fc in DNP3_FUNCS:
                    name, cat = DNP3_FUNCS[fc]
                    out.append(Command("DNP3", name, cat))
        i += max(frame_len, 10)
    return out


# ------------------------------------------------------------------ S7comm
S7_JOB_FUNCS = {
    0x04: ("Read Var", "recon"), 0x05: ("Write Var", "write"),
    0x1A: ("Request download", "program"), 0x1B: ("Download block", "program"),
    0x1C: ("Download ended", "program"), 0x1D: ("Start upload", "recon"),
    0x1E: ("Upload", "recon"), 0x1F: ("End upload", "recon"),
    0x28: ("PI service", "program"), 0x29: ("PLC Stop", "stop"),
}
S7_PI = {b"P_PROGRAM": ("PI service: start PLC (P_PROGRAM)", "restart"),
         b"_INSE": ("PI service: insert/activate block (_INSE)", "program"),
         b"_DELE": ("PI service: delete block (_DELE)", "program"),
         b"_GARB": ("PI service: compress memory (_GARB)", "program"),
         b"_MODU": ("PI service: copy RAM to ROM (_MODU)", "program")}
S7_USERDATA = {
    (3, 1): ("List blocks", "recon"), (3, 2): ("List blocks of type", "recon"), (3, 3): ("Get block info", "recon"),
    (4, 1): ("Read SZL", "recon"), (5, 1): ("Set/enter PLC password", "auth"), (5, 2): ("Clear PLC password", "auth"),
    (7, 2): ("Set clock", "time"),
}


def s7comm(payload: bytes, to_server: bool) -> list[Command]:
    out: list[Command] = []
    if not to_server or len(payload) < 7 or payload[0] != 0x03:
        return out
    li = payload[4]
    if payload[5] != 0xF0:                         # COTP DT data only
        return out
    s = 5 + li
    if len(payload) < s + 11:
        return out
    if payload[s] == 0x72:
        out.append(Command("S7comm-plus", "S7comm-plus session (TIA Portal / S7-1200/1500)", "other"))
        return out
    if payload[s] != 0x32:
        return out
    rosctr = payload[s + 1]
    if rosctr == 1:                                # Job
        fn = payload[s + 10]
        if fn in S7_JOB_FUNCS:
            name, cat = S7_JOB_FUNCS[fn]
            if fn == 0x28:
                plen = struct.unpack(">H", payload[s + 6:s + 8])[0]
                param = bytes(payload[s + 10:s + 10 + plen])
                for key, (pname, pcat) in S7_PI.items():
                    if key in param:
                        name, cat = pname, pcat
                        break
            out.append(Command("S7comm", name, cat))
    elif rosctr == 7 and len(payload) >= s + 17 and payload[s + 10:s + 13] == b"\x00\x01\x12":
        tg, sub = payload[s + 15], payload[s + 16]
        if tg >> 4 == 4:                           # request
            key = (tg & 0x0F, sub)
            if key in S7_USERDATA:
                name, cat = S7_USERDATA[key]
                out.append(Command("S7comm", name, cat))
    return out


# ------------------------------------------------------------------ EtherNet/IP + CIP
ENIP_CMDS = {0x0004: ("ListServices", "recon"), 0x0063: ("ListIdentity", "recon"),
             0x0064: ("ListInterfaces", "recon")}
CIP_GENERIC = {0x02: ("Set_Attribute_All", "write"), 0x05: ("Reset", "restart"), 0x06: ("Start", "restart"),
               0x07: ("Stop", "stop"), 0x10: ("Set_Attribute_Single", "write"), 0x15: ("Restore", "config"),
               0x16: ("Save", "config")}
CIP_TAG = {0x4C: ("Read Tag", "recon"), 0x52: ("Read Tag Fragmented", "recon"),
           0x4D: ("Write Tag", "write"), 0x53: ("Write Tag Fragmented", "write"),
           0x4E: ("Read-Modify-Write Tag", "write")}
CLASS_CONNECTION_MANAGER = 0x06


def _cip_path(msg: bytes, words: int) -> tuple[int | None, bool]:
    """Returns (class id, has symbolic segment) for an EPATH."""
    path = msg[2:2 + 2 * words]
    cls, symbolic, i = None, False, 0
    while i < len(path):
        seg = path[i]
        if seg == 0x20 and i + 1 < len(path):
            cls = path[i + 1] if cls is None else cls
            i += 2
        elif seg == 0x21 and i + 3 < len(path):
            cls = path[i + 2] | path[i + 3] << 8 if cls is None else cls
            i += 4
        elif seg in (0x24, 0x28, 0x30):
            i += 2
        elif seg in (0x25, 0x29, 0x31):
            i += 4
        elif seg == 0x91 and i + 1 < len(path):
            symbolic = True
            n = path[i + 1]
            i += 2 + n + (n & 1)
        else:
            break
    return cls, symbolic


def _cip(msg: bytes, depth: int = 0) -> list[Command]:
    if len(msg) < 2 or msg[0] & 0x80:              # response
        return []
    svc, words = msg[0], msg[1]
    cls, symbolic = _cip_path(msg, words)
    if cls == CLASS_CONNECTION_MANAGER:
        if svc == 0x52 and depth == 0:             # Unconnected Send: unwrap the embedded request
            j = 2 + 2 * words + 2
            if len(msg) >= j + 2:
                size = struct.unpack("<H", msg[j:j + 2])[0]
                return _cip(msg[j + 2:j + 2 + size], depth + 1)
        return []
    if svc in CIP_TAG and (symbolic or cls is None):
        name, cat = CIP_TAG[svc]
        return [Command("CIP", name, cat)]
    if svc in CIP_GENERIC:
        name, cat = CIP_GENERIC[svc]
        target = "Identity" if cls == 0x01 else (f"class 0x{cls:02X}" if cls is not None else "")
        return [Command("CIP", f"{name} ({target})" if target else name, cat)]
    if svc == 0x4B:
        return [Command("CIP", "Execute PCCC", "other")]
    return []


def enip(payload: bytes, to_server: bool) -> list[Command]:
    out: list[Command] = []
    if not to_server or len(payload) < 24:
        return out
    cmd, length = struct.unpack("<HH", payload[:4])
    if cmd in ENIP_CMDS:
        name, cat = ENIP_CMDS[cmd]
        return [Command("EtherNet/IP", name, cat)]
    if cmd not in (0x006F, 0x0070):
        return out
    data = payload[24:24 + length]
    if len(data) < 8:
        return out
    count = struct.unpack("<H", data[6:8])[0]
    i = 8
    for _ in range(min(count, 8)):
        if i + 4 > len(data):
            break
        typ, ln = struct.unpack("<HH", data[i:i + 4])
        item = data[i + 4:i + 4 + ln]
        if typ == 0x00B2:
            out.extend(_cip(item))
        elif typ == 0x00B1 and len(item) > 2:
            out.extend(_cip(item[2:]))
        i += 4 + ln
    return out


# ------------------------------------------------------------------ dispatch
TCP_DECODERS = {2404: iec104, 20000: dnp3, 102: s7comm, 44818: enip}
UDP_DECODERS = {20000: dnp3, 44818: enip}


def decode(ipproto: int, sport: int, dport: int, payload: bytes) -> list[Command]:
    table = TCP_DECODERS if ipproto == 6 else UDP_DECODERS
    if dport in table:
        return table[dport](payload, True)
    if sport in table:
        return table[sport](payload, False)
    return []
