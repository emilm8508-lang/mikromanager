"""
Device client factory — returns appropriate client implementation based on
device.vendor field. Both clients expose the same async API so endpoints
can dispatch transparently.
"""
from services.mikrotik_client import MikrotikClient
from services.cisco_client import CiscoClient
from models.database import Device
from services.crypto import decrypt
from typing import Union, Tuple


DeviceClient = Union[MikrotikClient, CiscoClient]


def build_client(device: Device, credential) -> DeviceClient:
    """Construct the right client class for this device + credential."""
    password = decrypt(credential.password_enc) if credential.password_enc else ""
    community = decrypt(credential.snmp_community_enc) if credential.snmp_community_enc else None

    vendor = (device.vendor or "mikrotik").lower()
    if vendor == "cisco-sb":
        return CiscoClient(
            ip=device.ip,
            username=credential.username,
            password=password,
            snmp_community=community,
            snmp_port=device.snmp_port or 161,
            web_port=device.web_port,
            ssh_port=device.ssh_port,
        )

    # Default: Mikrotik (also handles 'generic-snmp' decently because Mikrotik
    # client also has SNMP fallback inside).
    return MikrotikClient(
        device.ip, credential.username, password,
        api_port=device.api_port, web_port=device.web_port,
        snmp_community=community, snmp_port=device.snmp_port or 161,
    )
