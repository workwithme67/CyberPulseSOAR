"""Playbook registry and metadata for automated response actions."""

from types import ModuleType

from . import block_ip, escalate, isolate_host, notify_soc

REGISTRY: dict[str, ModuleType] = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "notify_soc": notify_soc,
    "escalate": escalate,
}

AVAILABLE_PLAYBOOKS: list[dict[str, str]] = [
    {
        "name": "block_ip",
        "description": block_ip.PLAYBOOK_DESCRIPTION,
        "action": "IP_BLOCKED",
        "target_type": "ip_address",
    },
    {
        "name": "isolate_host",
        "description": isolate_host.PLAYBOOK_DESCRIPTION,
        "action": "HOST_ISOLATED",
        "target_type": "hostname_or_ip",
    },
    {
        "name": "notify_soc",
        "description": notify_soc.PLAYBOOK_DESCRIPTION,
        "action": "SOC_NOTIFIED",
        "target_type": "ip_address",
    },
    {
        "name": "escalate",
        "description": escalate.PLAYBOOK_DESCRIPTION,
        "action": "INCIDENT_ESCALATED",
        "target_type": "ip_address",
    },
]

__all__ = ["AVAILABLE_PLAYBOOKS", "REGISTRY"]
