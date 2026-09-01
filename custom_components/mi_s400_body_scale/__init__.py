from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_MAC,
    CONF_TOKEN,
)
from .coordinator import S400Coordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]

type S400ConfigEntry = ConfigEntry[S400Coordinator]


async def async_setup_entry(hass: HomeAssistant, entry: S400ConfigEntry) -> bool:
    data = entry.data
    mac: str = data[CONF_MAC]
    token = bytes.fromhex(data[CONF_TOKEN])

    coordinator = S400Coordinator(hass, entry, mac, token)
    entry.runtime_data = coordinator

    await coordinator.async_start()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def _async_update_listener(hass: HomeAssistant, entry: S400ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: S400ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await entry.runtime_data.async_stop()
    return unload_ok
