from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass
from typing import Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

from .const import (
    AVDTP,
    AVCTP,
    CFM_LOGIN_OK,
    CMD_LOGIN,
    CMD_SEND_INFO,
    CMD_SEND_KEY,
    CMTP,
    CONNECT_TIMEOUT_SECONDS,
    LOGIN_TIMEOUT_SECONDS,
    RCV_OK,
    RCV_RDY,
    UPNP,
    VEND1A,
    VEND1C,
)
from .crypto import SessionKeys, decrypt_cmtp, derive_login_keys, hmac_sha256

_LOGGER = logging.getLogger(__name__)


class AuthError(RuntimeError):
    pass


class BadTokenError(AuthError):
    pass


@dataclass
class ScaleEvent:
    type: str
    weight_kg: float | None = None
    stable: bool = False
    impedance_ohm: float | None = None
    impedance_low_ohm: float | None = None
    profile_id: int | None = None
    timestamp: int | None = None
    raw_plaintext: bytes | None = None


def _to_int(p: str) -> int | None:
    p = p.strip()
    if not p:
        return None
    neg = p.startswith("-")
    digits = p[1:] if neg else p
    if not digits.isdigit():
        return None
    return -int(digits) if neg else int(digits)


def _parse_payload(pt: bytes) -> dict | None:
    idx = pt.find(b"\xa0")
    if idx < 0:
        return None
    s = pt[idx + 1:].decode("ascii", errors="replace").rstrip("\x00").strip()
    parts = s.split(",")

    if len(parts) == 2:
        w = _to_int(parts[0])
        return {
            "type": "live",
            "weight_kg": w / 10 if w is not None else None,
            "stable": parts[1] == "1",
        }

    if len(parts) >= 6:
        w = _to_int(parts[3]) if len(parts) > 3 else None
        stable_flag = parts[4] if len(parts) > 4 else "0"
        ts = _to_int(parts[6]) if len(parts) > 6 else None

        imp = None
        imp_low = None
        if len(parts) >= 2:
            imp = _to_int(parts[-2])
            imp_low = _to_int(parts[-1])

        profile_id = _to_int(parts[2]) if len(parts) > 2 else None

        return {
            "type": "final",
            "weight_kg": w / 10 if w is not None else None,
            "stable": stable_flag == "1",
            "timestamp": ts,
            "impedance_ohm": imp / 10 if imp is not None else None,
            "impedance_low_ohm": imp_low / 10 if imp_low is not None else None,
            "profile_id": profile_id,
        }
    return None


class _NotifyHub:
    def __init__(self) -> None:
        self.queues: dict[str, asyncio.Queue[bytes]] = {}

    def queue(self, uuid: str) -> asyncio.Queue[bytes]:
        if uuid not in self.queues:
            self.queues[uuid] = asyncio.Queue()
        return self.queues[uuid]

    def make_callback(self, uuid: str) -> Callable[[int, bytearray], None]:
        q = self.queue(uuid)

        def cb(_handle: int, data: bytearray) -> None:
            try:
                q.put_nowait(bytes(data))
            except asyncio.QueueFull:
                _LOGGER.warning("notify queue full on %s; dropping", uuid)

        return cb


async def _wait(q: asyncio.Queue[bytes], timeout: float) -> bytes:
    return await asyncio.wait_for(q.get(), timeout=timeout)


async def _write(client: BleakClient, uuid: str, data: bytes) -> None:
    await client.write_gatt_char(uuid, data, response=False)


async def _write_parcel(client: BleakClient, uuid: str, data: bytes,
                         chunk_size: int = 18, frame_delay: float = 0.05) -> None:
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        n = i // chunk_size + 1
        framed = bytes([n & 0xFF, (n >> 8) & 0xFF]) + chunk
        await _write(client, uuid, framed)
        await asyncio.sleep(frame_delay)


async def _recv_multiframe(client: BleakClient, q: asyncio.Queue[bytes],
                            timeout: float = 5.0) -> bytes:
    first = await _wait(q, timeout)
    if len(first) < 6 or first[:3] != b"\x00\x00\x00":
        raise AuthError(f"unexpected first frame: {first.hex()}")
    expected = first[4] | (first[5] << 8)
    await _write(client, AVDTP, RCV_RDY)
    buf = b""
    for _ in range(expected):
        frame = await _wait(q, timeout)
        buf += frame[2:]
    await _write(client, AVDTP, RCV_OK)
    return buf


async def login(client: BleakClient, token: bytes, hub: _NotifyHub,
                 timeout: float = LOGIN_TIMEOUT_SECONDS) -> SessionKeys:
    if len(token) != 12:
        raise AuthError(f"token must be 12 bytes, got {len(token)}")

    avdtp_q = hub.queue(AVDTP)
    upnp_q = hub.queue(UPNP)

    app_rand = secrets.token_bytes(16)

    await _write(client, UPNP, CMD_LOGIN)
    await _write(client, AVDTP, CMD_SEND_KEY)
    rdy = await _wait(avdtp_q, timeout)
    if rdy != RCV_RDY:
        raise AuthError(f"expected RCV_RDY after CMD_SEND_KEY, got {rdy.hex()}")
    await _write_parcel(client, AVDTP, app_rand)
    ok = await _wait(avdtp_q, timeout)
    if ok != RCV_OK:
        raise AuthError(f"expected RCV_OK, got {ok.hex()}")

    dev_rand = await _recv_multiframe(client, avdtp_q, timeout)
    if len(dev_rand) != 16:
        raise AuthError(f"bad dev rand len {len(dev_rand)}: {dev_rand.hex()}")

    remote_info = await _recv_multiframe(client, avdtp_q, timeout)

    keys = derive_login_keys(token, app_rand, dev_rand)
    expected_remote = hmac_sha256(keys.dev_key, dev_rand + app_rand)
    if remote_info != expected_remote:
        raise BadTokenError("HMAC mismatch - token is wrong or has rotated")

    our_info = hmac_sha256(keys.app_key, app_rand + dev_rand)

    await _write(client, AVDTP, CMD_SEND_INFO)
    rdy = await _wait(avdtp_q, timeout)
    if rdy != RCV_RDY:
        raise AuthError(f"expected RCV_RDY for SEND_INFO, got {rdy.hex()}")
    await _write_parcel(client, AVDTP, our_info)
    ok = await _wait(avdtp_q, timeout)
    if ok != RCV_OK:
        raise AuthError(f"expected RCV_OK for SEND_INFO, got {ok.hex()}")

    result = await _wait(upnp_q, timeout)
    if result != CFM_LOGIN_OK:
        raise AuthError(f"login failed: {result.hex()}")

    return keys


class S400BleClient:
    def __init__(
        self,
        mac: str,
        token: bytes,
        *,
        on_event: Callable[[ScaleEvent], None],
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
    ) -> None:
        self.mac = mac.upper()
        self._token = token
        self._on_event = on_event
        self.connect_timeout = connect_timeout

        self._client: BleakClient | None = None
        self._keys: SessionKeys | None = None
        self._hub = _NotifyHub()
        self._stop = asyncio.Event()
        self._pump_task: asyncio.Task | None = None

    @property
    def is_connected(self) -> bool:
        return bool(self._client and self._client.is_connected)

    async def connect_and_login(self, ble_device: BLEDevice | None = None) -> None:
        dev = ble_device
        if dev is None:
            dev = await BleakScanner.find_device_by_address(
                self.mac, timeout=20.0
            )
        if dev is None:
            raise RuntimeError(f"scale {self.mac} not found in BLE range")

        client = BleakClient(dev, timeout=self.connect_timeout)
        await client.connect()
        self._client = client

        for uuid in (UPNP, AVDTP, AVCTP, VEND1A, CMTP, VEND1C):
            try:
                await client.start_notify(uuid, self._hub.make_callback(uuid))
            except Exception as exc:
                _LOGGER.debug("subscribe %s failed (skipping): %s", uuid[:8], exc)

        await asyncio.sleep(0.3)
        self._keys = await login(client, self._token, self._hub)
        _LOGGER.info("logged into scale %s", self.mac)

        self._stop.clear()
        self._pump_task = asyncio.create_task(self._cmtp_pump())

    async def disconnect(self) -> None:
        self._stop.set()
        if self._pump_task:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except (asyncio.CancelledError, Exception):
                pass
            self._pump_task = None
        if self._client and self._client.is_connected:
            try:
                await self._client.disconnect()
            except Exception as exc:
                _LOGGER.debug("disconnect error: %s", exc)
        self._client = None
        self._keys = None

    async def _cmtp_pump(self) -> None:
        assert self._client is not None and self._keys is not None
        q = self._hub.queue(CMTP)
        expected = 0
        buf = b""
        while not self._stop.is_set():
            try:
                data = await asyncio.wait_for(q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if len(data) >= 6 and data[:3] == b"\x00\x00\x00" and data[5] == 0:
                expected = data[4]
                buf = b""
                try:
                    await self._client.write_gatt_char(CMTP, RCV_RDY, response=False)
                except Exception:
                    pass
                continue

            if len(data) >= 2 and data[1] == 0 and expected > 0:
                frame_num = data[0]
                buf += data[2:]
                if frame_num >= expected:
                    await self._handle_full(buf)
                    try:
                        await self._client.write_gatt_char(CMTP, RCV_OK, response=False)
                    except Exception:
                        pass
                    expected = 0
                    buf = b""

    async def _handle_full(self, ciphertext: bytes) -> None:
        assert self._keys is not None
        pt = decrypt_cmtp(self._keys, ciphertext)
        if pt is None:
            _LOGGER.warning("decrypt failed on frame of length %d", len(ciphertext))
            return
        parsed = _parse_payload(pt)
        if parsed is None:
            self._on_event(ScaleEvent(type="raw", raw_plaintext=pt))
            return

        ev_type = parsed.pop("type")
        event = ScaleEvent(type=ev_type, **parsed, raw_plaintext=pt)

        self._on_event(event)
