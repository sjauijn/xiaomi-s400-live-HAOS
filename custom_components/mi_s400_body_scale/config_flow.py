from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.device_registry import format_mac

from .ble_client import AuthError, BadTokenError, S400BleClient
from .const import (
    CONF_MAC,
    CONF_TOKEN,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _normalize_mac(raw: str) -> str:
    cleaned = raw.strip().upper().replace("-", ":")
    return cleaned


def _validate_hex(value: str, expected_bytes: int, field: str) -> bytes:
    value = value.strip().replace(" ", "").replace(":", "")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise vol.Invalid(f"{field}_not_hex") from exc
    if len(data) != expected_bytes:
        raise vol.Invalid(f"{field}_wrong_length")
    return data


STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_MAC): str,
        vol.Required(CONF_TOKEN): str,
    }
)

STEP_BLUETOOTH_CONFIRM_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_TOKEN): str,
    }
)


class S400ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._discovered_mac: str | None = None
        self._discovered_name: str | None = None

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        mac = _normalize_mac(discovery_info.address)
        await self.async_set_unique_id(format_mac(mac))
        self._abort_if_unique_id_configured()

        self._discovered_mac = mac
        self._discovered_name = discovery_info.name or mac
        self.context["title_placeholders"] = {"name": self._discovered_name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        assert self._discovered_mac is not None

        if user_input is not None:
            token_raw = user_input[CONF_TOKEN]

            token: bytes | None = None
            try:
                token = _validate_hex(token_raw, 12, "token")
            except vol.Invalid:
                errors[CONF_TOKEN] = "invalid_token"

            if not errors:
                try:
                    await self._async_try_login(self._discovered_mac, token)
                except BadTokenError:
                    errors["base"] = "bad_token"
                except AuthError:
                    errors["base"] = "auth_failed"
                except RuntimeError:
                    errors["base"] = "cannot_connect"
                except Exception:
                    _LOGGER.exception("unexpected error validating scale")
                    errors["base"] = "unknown"

            if not errors:
                device_data: dict[str, Any] = {
                    CONF_MAC: self._discovered_mac,
                    CONF_TOKEN: token.hex(),
                }
                return self.async_create_entry(
                    title=f"Mi Scale S400 ({self._discovered_mac})",
                    data=device_data,
                )

        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=STEP_BLUETOOTH_CONFIRM_SCHEMA,
            errors=errors,
            description_placeholders={"name": self._discovered_name},
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            mac = _normalize_mac(user_input[CONF_MAC])
            token_raw = user_input[CONF_TOKEN]

            token: bytes | None = None
            try:
                token = _validate_hex(token_raw, 12, "token")
            except vol.Invalid:
                errors[CONF_TOKEN] = "invalid_token"

            if not errors:
                await self.async_set_unique_id(format_mac(mac))
                self._abort_if_unique_id_configured()

                try:
                    await self._async_try_login(mac, token)
                except BadTokenError:
                    errors["base"] = "bad_token"
                except AuthError:
                    errors["base"] = "auth_failed"
                except RuntimeError:
                    errors["base"] = "cannot_connect"
                except Exception:
                    _LOGGER.exception("unexpected error validating scale")
                    errors["base"] = "unknown"

            if not errors:
                device_data: dict[str, Any] = {
                    CONF_MAC: mac,
                    CONF_TOKEN: token.hex(),
                }
                return self.async_create_entry(
                    title=f"Mi Scale S400 ({mac})",
                    data=device_data,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )

    async def _async_try_login(self, mac: str, token: bytes) -> None:
        result: dict[str, Any] = {}

        def _noop(_event) -> None:
            return None

        client = S400BleClient(mac, token, on_event=_noop)
        try:
            await client.connect_and_login()
        finally:
            await client.disconnect()
