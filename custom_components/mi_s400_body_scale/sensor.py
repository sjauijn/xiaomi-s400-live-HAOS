from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfMass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo, format_mac
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_MAC, DOMAIN
from .coordinator import S400Coordinator


@dataclass(frozen=True, kw_only=True)
class S400SensorDescription(SensorEntityDescription):
    value_fn: Callable[[Any], Any] = lambda ev: None


def _weight(ev):
    return ev.weight_kg if ev else None


def _impedance(ev):
    return ev.impedance_ohm if ev else None


def _impedance_low(ev):
    return ev.impedance_low_ohm if ev else None


def _profile_id(ev):
    return ev.profile_id if ev else None


SENSOR_DESCRIPTIONS: tuple[S400SensorDescription, ...] = (
    S400SensorDescription(
        key="weight",
        translation_key="weight",
        device_class=SensorDeviceClass.WEIGHT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        suggested_display_precision=1,
        value_fn=_weight,
    ),
    S400SensorDescription(
        key="impedance",
        translation_key="impedance",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="Ω",
        icon="mdi:omega",
        value_fn=_impedance,
    ),
    S400SensorDescription(
        key="impedance_low",
        translation_key="impedance_low",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="Ω",
        icon="mdi:omega",
        value_fn=_impedance_low,
    ),
    S400SensorDescription(
        key="profile_id",
        translation_key="profile_id",
        icon="mdi:identifier",
        value_fn=_profile_id,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: S400Coordinator = entry.runtime_data
    mac = entry.data[CONF_MAC]

    async_add_entities(
        S400Sensor(coordinator, entry, mac, description)
        for description in SENSOR_DESCRIPTIONS
    )


class S400Sensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    entity_description: S400SensorDescription

    def __init__(
        self,
        coordinator: S400Coordinator,
        entry: ConfigEntry,
        mac: str,
        description: S400SensorDescription,
    ) -> None:
        self.entity_description = description
        self._coordinator = coordinator
        self._attr_unique_id = f"{format_mac(mac)}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, format_mac(mac))},
            name=entry.title,
            manufacturer="Mi",
            model="S400 Body Composition Scale",
        )

    @property
    def available(self) -> bool:
        return self._coordinator.available

    @property
    def native_value(self):
        return self.entity_description.value_fn(self._coordinator.last_event)

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_update)
        )

    def _handle_update(self) -> None:
        self.async_write_ha_state()
