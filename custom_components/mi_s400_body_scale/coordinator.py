from __future__ import annotations

import asyncio
import logging

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.event import async_call_later

from .ble_client import S400BleClient, ScaleEvent
from .const import RECONNECT_DELAY_SECONDS

_LOGGER = logging.getLogger(__name__)


class S400Coordinator:
    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        mac: str,
        token: bytes,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.mac = mac
        self.last_event: ScaleEvent | None = None
        self._listeners: list = []
        self._stopped = False
        self._reconnect_handle = None
        self._unavailable_tracker_remove = None
        self._connecting = False

        self._seen_in_ble = bluetooth.async_address_present(
            hass, mac, connectable=False
        )

        self._client = S400BleClient(
            mac, token, on_event=self._handle_event
        )

    @property
    def available(self) -> bool:
        return self._seen_in_ble

    @callback
    def _handle_event(self, event: ScaleEvent) -> None:
        if event.type != "final":
            return
        self.last_event = event
        for listener in list(self._listeners):
            listener()

    def async_add_listener(self, update_callback) -> callable:
        self._listeners.append(update_callback)

        def remove() -> None:
            self._listeners.remove(update_callback)

        return remove

    @callback
    def _async_bluetooth_seen(
        self, service_info: bluetooth.BluetoothServiceInfoBleak, change
    ) -> None:
        was_seen = self._seen_in_ble
        self._seen_in_ble = True
        if not was_seen:
            self._notify_listeners()
            if not self._client.is_connected and not self._connecting:
                if self._reconnect_handle is not None:
                    self._reconnect_handle()
                    self._reconnect_handle = None
                self.hass.async_create_task(self._connect_loop())

    @callback
    def _async_bluetooth_unavailable(
        self, service_info: bluetooth.BluetoothServiceInfoBleak
    ) -> None:
        self._seen_in_ble = False
        self._notify_listeners()

    async def async_start(self) -> None:
        self._stopped = False

        self.entry.async_on_unload(
            bluetooth.async_register_callback(
                self.hass,
                self._async_bluetooth_seen,
                {"address": self.mac, "connectable": False},
                bluetooth.BluetoothScanningMode.PASSIVE,
            )
        )
        self._unavailable_tracker_remove = bluetooth.async_track_unavailable(
            self.hass, self._async_bluetooth_unavailable, self.mac, connectable=False
        )
        self.entry.async_on_unload(self._unavailable_tracker_remove)

        self.hass.async_create_task(self._connect_loop())

    async def _connect_loop(self) -> None:
        if self._stopped or self._connecting or self._client.is_connected:
            return

        if not self._seen_in_ble:
            _LOGGER.debug(
                "scale %s not currently visible over BLE; waiting for it to appear",
                self.mac,
            )
            return

        self._connecting = True
        try:
            await self._client.connect_and_login()
        except Exception as exc:
            _LOGGER.warning(
                "could not connect/login to scale %s: %s (retrying in %ss)",
                self.mac, exc, RECONNECT_DELAY_SECONDS,
            )
            self._schedule_reconnect()
            return
        finally:
            self._connecting = False

        self.hass.async_create_task(self._watch_connection())

    async def _watch_connection(self) -> None:
        while not self._stopped:
            await asyncio.sleep(5)
            if self._stopped:
                return
            if not self._client.is_connected:
                self._schedule_reconnect()
                return

    def _schedule_reconnect(self) -> None:
        if self._stopped:
            return

        async def _retry(_now) -> None:
            self._reconnect_handle = None
            if self._stopped:
                return
            await self._connect_loop()

        self._reconnect_handle = async_call_later(
            self.hass, RECONNECT_DELAY_SECONDS, _retry
        )

    def _notify_listeners(self) -> None:
        for listener in list(self._listeners):
            listener()

    async def async_stop(self) -> None:
        self._stopped = True
        if self._reconnect_handle:
            self._reconnect_handle()
            self._reconnect_handle = None
        await self._client.disconnect()
