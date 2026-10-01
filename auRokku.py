#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from typing import Any

try:
    import usb.core
    import usb.util
except ImportError:
    usb = None


def encode_nibbles(data: bytes) -> bytes:
    return bytes(n for b in data for n in (b >> 4, b & 0x0F))


def decode_nibbles(data: bytes) -> bytes:
    if len(data) % 2 != 0 or any(b > 0x0F for b in data):
        raise ValueError("Expected an even number of binary nibble bytes (00..0F)")
    return bytes((data[i] << 4) | data[i + 1] for i in range(0, len(data), 2))


def decode_lockcode_digits(data: bytes) -> str:
    digits = []
    for b in data:
        if 0x91 <= b <= 0x99:
            digits.append(chr(b - 0x60))
        elif b == 0x9A:
            digits.append('0')
        elif b == 0x9B:
            digits.append('*')
        elif b == 0x9C:
            digits.append('#')
        elif b == 0x9E:
            digits.append('P')
        elif b == 0x9F:
            digits.append('-')
        else:
            digits.append(f"[{b:02X}]")
    return "".join(digits)


def parse_sn_to_type2auth(sn_str: str) -> tuple[bytes, str]:
    s = sn_str.strip()
    if len(s) == 16:
        auth_raw = bytes.fromhex(s)
        return auth_raw, s.upper()
    forward = s[:5].upper().encode("ascii") + bytes.fromhex(s[5:])
    return forward[::-1], s.upper()


def parse_usb_endpoint(value: str) -> int:
    try:
        endpoint = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid USB endpoint: {value!r}") from exc
    if not 0 <= endpoint <= 0xFF:
        raise argparse.ArgumentTypeError("USB endpoint must be between 00 and FF")
    return endpoint


def bitrev8(b: int) -> int:
    return int(f"{b:08b}"[::-1], 2)


def derive_type2auth_key(auth_raw: bytes) -> bytes:
    if len(auth_raw) != 8:
        raise ValueError(f"Key material must be exactly 8 bytes, got {len(auth_raw)}")
    s = auth_raw[::-1]
    return bytes([
        bitrev8(s[2]), s[5], s[7], bitrev8(s[3]),
        s[0], bitrev8(s[6]), bitrev8(s[4]), s[1],
    ])


def compute_type2auth_request(service: str, challenge: bytes, auth_raw: bytes) -> bytes:
    if len(challenge) != 8:
        raise ValueError(f"Challenge must be 8 decoded bytes, got {len(challenge)}")
    if service not in ("base", "uimlk", "2000", "4000"):
        raise ValueError(f"Unsupported authentication service: {service}")

    if service == "4000":
        s = auth_raw[::-1]
        k = bytes([s[0], s[5], s[2], s[7], s[4], s[3], bitrev8(s[6]), s[1]])
        digest = hashlib.md5(k + challenge).digest()
        proof = digest[:8]
    else:
        k = derive_type2auth_key(auth_raw)
        digest = hashlib.md5(k + challenge).digest()
        proof = digest[8:]

    return b"\x53" + encode_nibbles(proof)


class AuRokkuDevice:
    def __init__(
        self,
        vid: int,
        pid: int,
        sn: str | None = None,
        interface: int | None = None,
        ep_out: int = 0x04,
        ep_in: int = 0x84,
        verbose: bool = False,
        type2: bool = False,
    ):
        if usb is None:
            raise RuntimeError("pyusb is not installed")

        self.vid = vid
        self.pid = pid
        self.sn = sn
        self.interface_num = interface
        self.interface_alt = 0
        self.ep_out = ep_out
        self.ep_in = ep_in
        self.verbose = verbose
        self.type2 = type2

        self.device = None
        self.claimed = False
        self.type2auth_material: bytes | None = None
        self.rx_buffer = bytearray()
        self.async_events: list[dict[str, Any]] = []
        self.exit_result: dict[str, Any] | None = None
        self.audit: list[dict[str, Any]] = []
        self.awaiting_handshake = False

    def log(self, direction: str, data: bytes):
        if self.verbose:
            print(f"{direction}-> {data.hex(' ')}", file=sys.stderr)

    def send(self, data: bytes):
        self.log("TX", data)
        written = self.device.write(self.ep_out, data, timeout=2000)
        if written != len(data):
            raise RuntimeError(f"Short write: wrote {written}/{len(data)} bytes")

    def recv(self, expected_len: int, timeout_sec: float = 3.0) -> bytes:
        deadline = time.monotonic() + timeout_sec
        while len(self.rx_buffer) < expected_len:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timeout waiting for {expected_len} bytes; buffered {self.rx_buffer.hex(' ')}")
            try:
                part = bytes(self.device.read(self.ep_in, 512, timeout=500))
                self.log("RX", part)
                self.rx_buffer.extend(part)
                if self.awaiting_handshake:
                    while self.rx_buffer and self.rx_buffer[0] == 0xAF:
                        self.async_events.append({"opcode": "af", "meaning": "pre_echo_delimiter"})
                        del self.rx_buffer[0]
            except usb.core.USBTimeoutError:
                pass
        result = bytes(self.rx_buffer[:expected_len])
        del self.rx_buffer[:expected_len]
        return result

    def drain(self, timeout_ms: int = 50):
        self.rx_buffer.clear()
        dev = getattr(self, "device", None)
        if dev is not None and hasattr(dev, "read"):
            for _ in range(20):
                try:
                    part = bytes(dev.read(self.ep_in, 512, timeout=timeout_ms))
                    if not part:
                        break
                    self.log("RX", part)
                except Exception:
                    break

    def read_until(self, terminator: int, limit: int = 256, timeout: float = 3.0) -> bytes:
        deadline = time.monotonic() + timeout
        data = bytearray()
        while len(data) < limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Missing response terminator")
            data.extend(self.recv(1, remaining))
            if data[-1] == terminator:
                return bytes(data)
        raise RuntimeError("Response exceeds bounded limit")

    def open_device(self, require_sn: bool = True):
        if self.device is None:
            self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
            if self.device is None:
                raise RuntimeError(f"Device {self.vid:04x}:{self.pid:04x} not found")
        elif not require_sn or self.type2auth_material is not None:
            return

        if not require_sn:
            return

        device_sn = None
        try:
            device_sn = usb.util.get_string(self.device, self.device.iSerialNumber)
        except Exception as e:
            if self.verbose:
                print(f"[WARN] Failed to read iSerialNumber: {e}", file=sys.stderr)

        if self.sn:
            if device_sn and self.sn.upper() != device_sn.upper() and self.verbose:
                print(f"[WARN] Specified SN ({self.sn}) differs from USB iSerialNumber ({device_sn})",
                      file=sys.stderr)
            use_sn = self.sn
        elif device_sn:
            use_sn = device_sn
        else:
            raise RuntimeError("Cannot determine device SN. Please provide --sn <11_chars_or_16_hex> explicitly.")

        self.type2auth_material, canonical_sn = parse_sn_to_type2auth(use_sn)
        self.sn = canonical_sn

        if self.verbose:
            print(f"[INFO] Device SN: {self.sn}", file=sys.stderr)
            print(f"[INFO] Type2Auth Raw: {self.type2auth_material.hex(' ')}", file=sys.stderr)

    def connect(self, require_sn: bool = True):
        self.open_device(require_sn=require_sn)

        cfg = self.device.get_active_configuration()
        selected_intf = None
        if self.interface_num is None:
            for intf in cfg:
                eps = {ep.bEndpointAddress for ep in intf}
                if {self.ep_out, self.ep_in}.issubset(eps):
                    self.interface_num = intf.bInterfaceNumber
                    self.interface_alt = intf.bAlternateSetting
                    selected_intf = intf
                    break
            if self.interface_num is None:
                raise RuntimeError(
                    f"No interface with EP OUT 0x{self.ep_out:02X} and EP IN 0x{self.ep_in:02X}; "
                    "run --op probe to list bulk endpoint pairs"
                )
        else:
            for intf in cfg:
                if intf.bInterfaceNumber != self.interface_num:
                    continue
                eps = {ep.bEndpointAddress for ep in intf}
                if {self.ep_out, self.ep_in}.issubset(eps):
                    self.interface_alt = intf.bAlternateSetting
                    selected_intf = intf
                    break

        if self.verbose:
            print(f"[INFO] Using Interface {self.interface_num} alt {self.interface_alt}, "
                  f"EP OUT 0x{self.ep_out:02X}, EP IN 0x{self.ep_in:02X}",
                  file=sys.stderr)

        if selected_intf is None:
            raise RuntimeError(
                f"Interface {self.interface_num} lacks EP OUT 0x{self.ep_out:02X} "
                f"and EP IN 0x{self.ep_in:02X}; run --op probe to inspect it"
            )

        try:
            if self.device.is_kernel_driver_active(self.interface_num):
                self.device.detach_kernel_driver(self.interface_num)
        except (NotImplementedError, AttributeError):
            pass

        usb.util.claim_interface(self.device, self.interface_num)
        self.claimed = True
        if self.interface_alt:
            self.device.set_interface_altsetting(
                interface=self.interface_num,
                alternate_setting=self.interface_alt,
            )
        self.drain()

    def inspect_usb(self) -> dict[str, Any]:
        self.open_device(require_sn=False)
        active_value = None
        try:
            active_value = self.device.get_active_configuration().bConfigurationValue
        except Exception:
            pass

        configurations = []
        candidates = []
        for cfg in self.device:
            cfg_info: dict[str, Any] = {
                "value": cfg.bConfigurationValue,
                "active": cfg.bConfigurationValue == active_value,
                "interfaces": [],
            }
            for intf in cfg:
                intf_info: dict[str, Any] = {
                    "number": intf.bInterfaceNumber,
                    "alternate_setting": intf.bAlternateSetting,
                    "class": f"0x{intf.bInterfaceClass:02x}",
                    "subclass": f"0x{intf.bInterfaceSubClass:02x}",
                    "protocol": f"0x{intf.bInterfaceProtocol:02x}",
                    "endpoints": [],
                }
                bulk_in = []
                bulk_out = []
                for ep in intf:
                    address = ep.bEndpointAddress
                    transfer_type = ep.bmAttributes & 0x03
                    direction = "in" if address & 0x80 else "out"
                    intf_info["endpoints"].append({
                        "address": f"0x{address:02x}",
                        "direction": direction,
                        "type": {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}[transfer_type],
                        "max_packet_size": ep.wMaxPacketSize,
                        "interval": ep.bInterval,
                    })
                    if transfer_type == 2:
                        (bulk_in if direction == "in" else bulk_out).append(address)
                for ep_out in bulk_out:
                    for ep_in in bulk_in:
                        candidates.append({
                            "configuration": cfg.bConfigurationValue,
                            "active": cfg.bConfigurationValue == active_value,
                            "interface": intf.bInterfaceNumber,
                            "alternate_setting": intf.bAlternateSetting,
                            "ep_out": f"0x{ep_out:02x}",
                            "ep_in": f"0x{ep_in:02x}",
                        })
                cfg_info["interfaces"].append(intf_info)
            configurations.append(cfg_info)

        return {
            "vid": f"0x{self.vid:04x}",
            "pid": f"0x{self.pid:04x}",
            "active_configuration": active_value,
            "configurations": configurations,
            "bulk_candidates": candidates,
        }

    def _read_probe_response(self, timeout_sec: float = 1.0, limit: int = 512) -> bytes:
        data = bytearray(self.rx_buffer)
        self.rx_buffer.clear()
        deadline = time.monotonic() + timeout_sec
        while len(data) < limit and time.monotonic() < deadline:
            remaining_ms = max(1, min(200, int((deadline - time.monotonic()) * 1000)))
            try:
                part = bytes(self.device.read(self.ep_in, min(512, limit - len(data)), timeout=remaining_ms))
                if part:
                    self.log("RX", part)
                    data.extend(part)
            except usb.core.USBTimeoutError:
                if data:
                    break
        return bytes(data)

    def probe(self, kind: str = "list", timeout_sec: float = 1.0) -> dict[str, Any]:
        result: dict[str, Any] = {
            "operation": "probe",
            "probe": kind,
            "success": True,
            "selection": {
                "interface": self.interface_num,
                "alternate_setting": self.interface_alt,
                "ep_out": f"0x{self.ep_out:02x}",
                "ep_in": f"0x{self.ep_in:02x}",
            },
            "usb": self.inspect_usb(),
        }
        if kind == "list":
            return result
        if not self.claimed:
            raise RuntimeError("Active probe requires a claimed interface")

        self.drain()
        if kind == "seri":
            request = b"\x1c\x05"
            self.send(request)
            response = self._read_probe_response(timeout_sec)
            result.update({
                "request_hex": request.hex(" "),
                "response_hex": response.hex(" "),
                "responsive": bool(response),
                "matched": response.startswith(request),
            })
            result["success"] = result["matched"]
            if result["matched"] and self.vid != 0x0FCE:
                self.send(b"\xd8")
                result["cleanup_hex"] = "d8"
        elif kind == "scdp":
            request = b"\x8e"
            self.send(request)
            response = self._read_probe_response(timeout_sec)
            result.update({
                "request_hex": request.hex(" "),
                "response_hex": response.hex(" "),
                "responsive": bool(response),
                "response_length": len(response),
            })
            result["success"] = result["responsive"]
        else:
            raise ValueError(f"Unknown probe kind: {kind}")
        return result

    def close(self):
        if self.device is not None:
            if self.claimed:
                try:
                    usb.util.release_interface(self.device, self.interface_num)
                except Exception:
                    pass
                self.claimed = False
            if self.vid != 0x0FCE:
                try:
                    usb.util.dispose_resources(self.device)
                except Exception:
                    pass
            self.device = None

    def authenticate_step(self, service_name: str) -> str:
        self.send(b"\x52")
        deadline = time.monotonic() + 3.0
        resp = self.recv(17)
        extra_echoes = 0
        while service_name == "uimlk" and resp.startswith(b"\xe7"):
            if extra_echoes >= 4:
                raise RuntimeError("Too many E7 acknowledgements before UIMLK challenge")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timeout completing UIMLK challenge after E7 acknowledgement")
            extra_echoes += 1
            self.async_events.append({"opcode": "e7", "meaning": "extra_uimlk_ack_before_challenge"})
            resp = resp[1:] + self.recv(1, timeout_sec=remaining)
        if len(resp) != 17 or resp[0] != 0x52:
            raise RuntimeError(f"Invalid challenge frame for {service_name}: {resp.hex(' ')}")
        challenge = decode_nibbles(resp[1:])

        auth_pkt = compute_type2auth_request(service_name, challenge, self.type2auth_material)
        self.send(auth_pkt)
        auth_resp = self.recv(2)
        if auth_resp != b"\x53\x01":
            raise RuntimeError(f"Authentication failed for {service_name}: {auth_resp.hex(' ')}")
        return challenge.hex()

    def enter_base(self):
        self.drain()
        if self.vid != 0x0FCE:
            try:
                self.send(b"\xd8")
                time.sleep(0.05)
                self.drain()
            except Exception:
                pass

        self.send(b"\x1c\x05")
        self.awaiting_handshake = True
        try:
            echo = self.recv(2)
        finally:
            self.awaiting_handshake = False
        if echo != b"\x1c\x05":
            raise RuntimeError(f"Base handshake echo mismatch: {echo.hex(' ')}")

        if self.type2:
            self.authenticate_step("base")
        elif self.verbose:
            print("[INFO] Default mode: skipping base authentication", file=sys.stderr)

    def enter_uimlk(self):
        self.enter_base()
        self.send(b"\xe7")
        sw_echo = self.recv(1)
        if sw_echo != b"\xe7":
            raise RuntimeError(f"Service switch to UIMLK failed: {sw_echo.hex(' ')}")

        self.authenticate_step("uimlk")

    def exit_base(self):
        try:
            self.send(b"\xd8")
            time.sleep(0.05)
        except Exception:
            pass

    def exit_mode(self) -> bytes | None:
        if self.vid != 0x0FCE:
            self.exit_base()
            return b"\xd8"
        return None

    def exit_uimlk(self) -> bytes:
        self.send(b"\x56")
        resp = self.recv(1)
        if resp != b"\x56":
            raise RuntimeError(f"Invalid exit reply: {resp.hex()}")
        return resp

    def _finish_uimlk(self):
        try:
            reply = self.exit_uimlk()
            self.exit_result = {"acknowledged": True, "reply": reply.hex(), "may_reboot": True}
        except Exception as exc:
            self.exit_result = {"acknowledged": False, "error": str(exc), "may_reboot": True}

    def _read_state(self) -> dict[str, Any]:
        self.send(b"\x54")
        resp = self.recv(10)
        if len(resp) != 10 or resp[0] != 0x74 or resp[1] not in (0, 1):
            raise RuntimeError(f"Invalid state reply: {resp.hex(' ')}")
        value = decode_nibbles(resp[2:]).hex()
        return {
            "control": resp[1],
            "lock_value": value,
            "binding_cleared": (value == "ffffffff"),
            "raw_hex": resp.hex(" "),
        }

    def read_uimlk(self) -> dict[str, Any]:
        self.enter_uimlk()
        try:
            return {"operation": "readuimlk", "success": True, **self._read_state()}
        finally:
            self._finish_uimlk()

    def _mutate(
        self,
        operation: str,
        packet: bytes,
        expected_reply: bytes,
        expected_value: str,
        control: int | None = None,
    ) -> dict[str, Any]:
        self.enter_uimlk()
        result: dict[str, Any] = {
            "operation": operation,
            "success": False,
            "persistence_verified": False,
        }
        try:
            before = self._read_state()
            result["before"] = before

            try:
                self.send(packet)
                reply = self.recv(2)
                result["reply"] = reply.hex()
                result["command_accepted"] = (reply == expected_reply)
            except Exception as exc:
                result["command_accepted"] = False
                result["command_error"] = str(exc)

            try:
                after = self._read_state()
                result["after"] = after
                exp_ctrl = before["control"] if control is None else control
                result["verified"] = (after["lock_value"] == expected_value and after["control"] == exp_ctrl)
            except Exception as exc:
                result["verified"] = False
                result["readback_error"] = str(exc)

            result["success"] = bool(result.get("command_accepted", False) and result.get("verified", False))
            result["partial_write_possible"] = not result["success"]
            return result
        finally:
            self._finish_uimlk()

    def write_uimlk(self, lock_val_hex: str, control: int = 1) -> dict[str, Any]:
        clean_hex = lock_val_hex.replace(" ", "")
        value = bytes.fromhex(clean_hex)
        if len(value) != 4 or control not in (0, 1):
            raise ValueError("Expected 4 value bytes and control 0 or 1")
        packet = bytes([0x72, control]) + encode_nibbles(value)
        return self._mutate("writelk", packet, b"\x72\x01", value.hex(), control)

    def clear_uimlk(self) -> dict[str, Any]:
        return self._mutate("clearlk", b"\x57", b"\x57\x01", "ffffffff")

    def read_iccid(self) -> dict[str, Any]:
        self.enter_uimlk()
        try:
            self.send(b"\x59")
            resp = self.recv(21)
            if len(resp) != 21 or resp[0] != 0x59:
                raise RuntimeError(f"Invalid record59 reply: {resp.hex(' ')}")
            return {
                "operation": "readiccid",
                "success": True,
                "raw_hex": resp.hex(" "),
                "decoded_hex": decode_nibbles(resp[1:]).hex(" "),
            }
        finally:
            self._finish_uimlk()

    def query_record59(self) -> dict[str, Any]:
        self.send(b"\x59")
        r = self.recv(21)
        if r[0] != 0x59:
            raise RuntimeError("Invalid record59 reply")
        return {"decoded_hex": decode_nibbles(r[1:]).hex(" "), "raw_hex": r.hex(" ")}

    def read_lockcode(self, exit_after: bool = False) -> dict[str, Any]:
        try:
            try:
                self.send(b"\xdc\x00")
                r = self.read_until(0xAA, timeout=1.0)
            except Exception:
                self.enter_base()
                self.send(b"\xdc\x00")
                r = self.read_until(0xAA)

            idx = r.find(b"\xdc\x00")
            if idx == -1 or not r.endswith(b"\xaa") or len(r[idx:]) < 3:
                raise RuntimeError(f"Invalid lockcode reply: {r.hex(' ')}")
            frame = r[idx:]
            digits = decode_lockcode_digits(frame[2:-1])
            return {"operation": "readpin", "lockcode": digits, "raw_hex": frame.hex(" "), "success": True}
        finally:
            if exit_after:
                self.exit_mode()

    def reset_lockcode(self, exit_after: bool = False) -> dict[str, Any]:
        try:
            try:
                self.send(b"\xdc\x01")
                r = self.recv(2, timeout_sec=1.0)
            except Exception:
                self.enter_base()
                self.send(b"\xdc\x01")
                r = self.recv(2)

            if r != b"\xdc\x01":
                raise RuntimeError(f"Reset lockcode failed: {r.hex(' ')}")
            readback = self.read_lockcode(exit_after=False)
            return {
                "operation": "resetpin",
                "reply": r.hex(" "),
                "lockcode": readback["lockcode"],
                "verified": (readback["lockcode"] == "1234"),
                "success": True,
            }
        finally:
            if exit_after:
                self.exit_mode()

    def write_maintenance_bit(self, control: int) -> dict[str, Any]:
        if control not in (0, 1):
            raise ValueError("maintenance_bit requires --control 0 or 1")

        self.enter_base()
        self.send(b"\xe1")
        if self.recv(1) != b"\xe1":
            raise RuntimeError("Maintenance service (0xE1) entry failed")
        self.authenticate_step("4000")

        packet = bytes([0x72, control])
        expected = b"\x72\x01"

        result: dict[str, Any] = {
            "operation": "maintenance_bit",
            "success": False,
            "maintenance_bit": control,
        }

        self.send(packet)
        reply = self.recv(2)
        result["reply"] = reply.hex(" ")
        result["command_accepted"] = (reply == expected)
        result["success"] = result["command_accepted"]
        return result

    def query_basic(self, name: str) -> dict[str, Any]:
        if name == "version":
            self.send(b"\x1b")
            r = self.recv(5)
            if r[0] != 0x1b:
                raise RuntimeError("Invalid version reply")
            return {"raw_hex": r.hex(" ")}
        if name == "lockcode":
            self.send(b"\xdc\x00")
            r = self.read_until(0xAA)
            digits = decode_lockcode_digits(r[2:-1]) if len(r) >= 3 else None
            return {"raw_hex": r.hex(" "), "decoded": digits}
        raise ValueError(f"Unknown query: {name}")

    def batch_read(self, profile: str = "basic") -> dict[str, Any]:
        report: dict[str, Any] = {
            "operation": "batch",
            "profile": profile,
            "success": False,
            "results": [],
            "automatic_exit": False,
        }
        try:
            self.enter_base()
            if profile == "basic":
                jobs = [
                    ("version", lambda: self.query_basic("version")),
                    ("lockcode", lambda: self.query_basic("lockcode")),
                ]
            elif profile == "uimlk":
                self.send(b"\xe7")
                if self.recv(1) != b"\xe7":
                    raise RuntimeError("UIM entry failed")
                self.authenticate_step("uimlk")
                jobs = [
                    ("state", self._read_state),
                    ("record59", self.query_record59),
                ]
            else:
                raise ValueError(f"Unsupported batch profile: '{profile}'. Valid: basic, uimlk")

            for name, fn in jobs:
                res = fn()
                report["results"].append({"query": name, **res})
            report["success"] = True
        except Exception as exc:
            report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return report

    def read_status(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "operation": "status",
            "sn": self.sn,
            "success": False,
        }
        in_uimlk = False
        try:
            self.enter_base()

            try:
                ver = self.query_basic("version")
                report["version"] = ver["raw_hex"]
            except Exception as e:
                report["version"] = f"Error: {e}"

            try:
                pin_res = self.read_lockcode()
                report["lockcode"] = pin_res["lockcode"]
            except Exception as e:
                report["lockcode"] = f"Error: {e}"

            self.send(b"\xe7")
            if self.recv(1) != b"\xe7":
                raise RuntimeError("Switch to UIMLK failed")
            self.authenticate_step("uimlk")
            in_uimlk = True

            uim_state = self._read_state()
            report["uim_lock"] = {
                "control": uim_state["control"],
                "lock_value": uim_state["lock_value"],
                "unlocked": uim_state["binding_cleared"],
            }

            try:
                rec59 = self.query_record59()
                report["iccid_record"] = rec59["decoded_hex"]
            except Exception as e:
                report["iccid_record"] = f"Error: {e}"

            report["success"] = True
        finally:
            if in_uimlk:
                self._finish_uimlk()
            else:
                self.exit_base()
        return report

    def exit_service_only(self, op: str = "exit") -> dict[str, Any]:
        if op == "exituimlk":
            self.enter_uimlk()
            resp = self.exit_uimlk()
            return {
                "operation": "exituimlk",
                "success": (resp == b"\x56"),
                "method": "handshake_and_exit",
                "reply": resp.hex(),
            }
        else:
            self.exit_base()
            return {"operation": "exit", "success": True, "method": "0xd8"}


def print_human_report(op: str, result: dict[str, Any]):
    print("=" * 60)
    print(f"  Operation: {op}")
    print("=" * 60)

    success = result.get("success", False)
    status_str = "SUCCESS" if success else "FAILED"
    print(f"  Result Status : {status_str}")

    if op == "readuimlk":
        val = result.get("lock_value", "")
        ctrl = result.get("control", "")
        if val == "ffffffff":
            print("  UIM Lock      : UNLOCKED / CLEARED (ffffffff)")
        else:
            print(f"  UIM Lock      : LOCKED (Bound Card: {val})")
        print(f"  Control Bit   : {ctrl}")
        print(f"  Raw Hex       : {result.get('raw_hex', '')}")

    elif op == "clearlk":
        before = result.get("before", {})
        after = result.get("after", {})
        print(f"  Before Lock   : {before.get('lock_value', '')} (control: {before.get('control', '')})")
        print(f"  After Lock    : {after.get('lock_value', '')} (control: {after.get('control', '')})")
        print(f"  Verified      : {result.get('verified', False)}")

    elif op == "writelk":
        before = result.get("before", {})
        after = result.get("after", {})
        print(f"  Before Lock   : {before.get('lock_value', '')}")
        print(f"  Written Lock  : {after.get('lock_value', '')} (control: {after.get('control', '')})")
        print(f"  Verified      : {result.get('verified', False)}")

    elif op == "readiccid":
        print(f"  Decoded ICCID : {result.get('decoded_hex', '')}")
        print(f"  Raw Response  : {result.get('raw_hex', '')}")

    elif op == "readpin":
        print(f"  Phone PIN     : {result.get('lockcode', '')}")

    elif op == "resetpin":
        print(f"  New PIN       : {result.get('lockcode', '')}")
        print(f"  Verified 1234 : {result.get('verified', False)}")

    elif op == "maintenance_bit":
        print(f"  Requested     : maintenance_bit = {result.get('maintenance_bit')}")
        print(f"  Accepted      : {result.get('command_accepted', False)}")

    elif op == "status":
        print(f"  Device SN     : {result.get('sn', 'N/A')}")
        print(f"  Base Version  : {result.get('version', 'N/A')}")
        print(f"  Phone PIN     : {result.get('lockcode', 'N/A')}")
        uim = result.get("uim_lock", {})
        if uim:
            lock_str = "UNLOCKED" if uim.get("unlocked") else f"LOCKED ({uim.get('lock_value')})"
            print(f"  UIM Lock      : {lock_str} (control={uim.get('control')})")
        if result.get("iccid_record"):
            print(f"  SIM ICCID     : {result.get('iccid_record')}")

    elif op == "batch":
        print(f"  Profile       : {result.get('profile', '')}")
        for item in result.get("results", []):
            q_name = item.get("query", "")
            val = item.get("decoded") or item.get("lock_value") or item.get("raw_hex")
            print(f"    - {q_name:12s}: {val}")

    elif op == "probe":
        usb_info = result.get("usb", {})
        print(f"  Device        : {usb_info.get('vid', '')}:{usb_info.get('pid', '')}")
        print(f"  Probe Type    : {result.get('probe', '')}")
        selection = result.get("selection", {})
        if result.get("probe") != "list":
            print(f"  Selected      : if {selection.get('interface')} alt {selection.get('alternate_setting')} "
                  f"OUT {selection.get('ep_out')} IN {selection.get('ep_in')}")
        candidates = usb_info.get("bulk_candidates", [])
        if candidates:
            print("  Bulk Pairs    :")
            for item in candidates:
                active = " active" if item.get("active") else ""
                print(f"    cfg {item['configuration']} if {item['interface']} alt {item['alternate_setting']} "
                      f"OUT {item['ep_out']} IN {item['ep_in']}{active}")
        else:
            print("  Bulk Pairs    : none")
        if result.get("request_hex"):
            print(f"  Request       : {result.get('request_hex')}")
            print(f"  Response      : {result.get('response_hex') or '<timeout>'}")
            print(f"  Responsive    : {result.get('responsive', False)}")
        if result.get("probe") == "seri":
            print(f"  SERI Echo     : {result.get('matched', False)}")

    elif op in ("exituimlk", "exit"):
        print(f"  Method        : {result.get('method', '')}")

    if result.get("exit"):
        exit_info = result["exit"]
        if isinstance(exit_info, dict) and exit_info.get("acknowledged"):
            print(f"  Service Exit  : SUCCESS ({exit_info.get('reply', '56')})")
        elif isinstance(exit_info, dict) and exit_info.get("error"):
            print(f"  Service Exit  : FAILED ({exit_info['error']})")

    print("=" * 60)


def parse_args():
    parser = argparse.ArgumentParser(
        description="auRokku device service tool"
    )

    parser.add_argument(
        "--op",
        choices=[
            "status",
            "readuimlk",
            "clearlk",
            "writelk",
            "readiccid",
            "readpin", "resetpin",
            "maintenance_bit",
            "batch",
            "probe",
            "exituimlk", "exit",
        ],
        required=True,
        help="operation"
    )
    parser.add_argument(
        "--vid",
        type=lambda x: int(x, 16),
        required=True,
        help="USB vendor ID in hex"
    )
    parser.add_argument(
        "--pid",
        type=lambda x: int(x, 16),
        required=True,
        help="USB product ID in hex"
    )
    parser.add_argument(
        "--sn",
        type=str,
        default=None,
        help="11-character serial number or 16-hex Type2Auth value"
    )
    parser.add_argument(
        "--val",
        type=str,
        default=None,
        help="4-byte value for writelk"
    )
    parser.add_argument(
        "--control",
        type=int,
        choices=[0, 1],
        default=None,
        help="control value for writelk or maintenance_bit"
    )
    parser.add_argument(
        "--interface",
        type=int,
        default=None,
        help="USB interface number"
    )
    parser.add_argument(
        "--ep-out",
        type=parse_usb_endpoint,
        default=0x04,
        help="USB OUT endpoint in hex"
    )
    parser.add_argument(
        "--ep-in",
        type=parse_usb_endpoint,
        default=0x84,
        help="USB IN endpoint in hex"
    )
    parser.add_argument(
        "--probe-kind",
        choices=["list", "seri", "scdp"],
        default="list",
        help="probe USB layout, SERI, or SCDP"
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=1.0,
        help="active probe timeout in seconds"
    )
    parser.add_argument(
        "--profile",
        choices=["basic", "uimlk"],
        default="basic",
        help="batch profile"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show USB traffic"
    )
    parser.add_argument(
        "--type2", action="store_true",
        help="enable 52/53 authentication"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output JSON"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.op == "writelk" and not args.val:
        sys.exit("Error: --op writelk requires --val <8_hex_chars> (e.g. --val 80e48ed2)")

    if args.op == "maintenance_bit" and args.control is None:
        sys.exit("Error: --op maintenance_bit requires --control 0 or 1")

    if args.ep_out & 0x80:
        sys.exit("Error: --ep-out must be an OUT endpoint (bit 7 clear, e.g. 04)")
    if not args.ep_in & 0x80:
        sys.exit("Error: --ep-in must be an IN endpoint (bit 7 set, e.g. 84)")
    if args.probe_timeout <= 0:
        sys.exit("Error: --probe-timeout must be greater than zero")

    dev = AuRokkuDevice(
        vid=args.vid,
        pid=args.pid,
        sn=args.sn,
        interface=args.interface,
        ep_out=args.ep_out,
        ep_in=args.ep_in,
        verbose=args.verbose,
        type2=args.type2,
    )

    try:
        if args.op == "probe":
            dev.open_device(require_sn=False)
            if args.probe_kind != "list":
                dev.connect(require_sn=False)
            result = dev.probe(args.probe_kind, timeout_sec=args.probe_timeout)
        else:
            dev.connect()

        if args.op == "probe":
            pass
        elif args.op == "status":
            result = dev.read_status()
        elif args.op == "readuimlk":
            result = dev.read_uimlk()
        elif args.op == "clearlk":
            result = dev.clear_uimlk()
        elif args.op == "writelk":
            result = dev.write_uimlk(args.val, control=1 if args.control is None else args.control)
        elif args.op == "readiccid":
            result = dev.read_iccid()
        elif args.op == "readpin":
            result = dev.read_lockcode(exit_after=True)
        elif args.op == "resetpin":
            result = dev.reset_lockcode(exit_after=True)
        elif args.op == "maintenance_bit":
            result = dev.write_maintenance_bit(args.control)
        elif args.op == "batch":
            result = dev.batch_read(args.profile)
        elif args.op in ("exituimlk", "exit"):
            result = dev.exit_service_only(args.op)
        else:
            sys.exit(f"Unknown operation: {args.op}")

        result["exit"] = dev.exit_result
        result["async_events"] = dev.async_events

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_human_report(args.op, result)

        if not result.get("success", False):
            sys.exit(1)

    except Exception as exc:
        if args.json:
            print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, indent=2))
        else:
            print(f"Error ({type(exc).__name__}): {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        dev.close()


if __name__ == "__main__":
    main()
