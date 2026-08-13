"""Capabilities an autonomous agent may request."""

from dataclasses import dataclass
from enum import Enum, IntEnum


class Capability(str, Enum):
    READ_LOCAL = "read_local"
    WRITE_LOCAL = "write_local"
    NETWORK_READ = "network_read"
    NETWORK_WRITE = "network_write"
    EMAIL_SEND = "email_send"
    SHELL_EXECUTE = "shell_execute"
    CREDENTIAL_ACCESS = "credential_access"
    MEMORY_WRITE = "memory_write"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"


class CapabilityImpact(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class CapabilityProfile:
    impact: CapabilityImpact
    creates_side_effect: bool = False
    accesses_sensitive_data: bool = False


CAPABILITY_PROFILES = {
    Capability.READ_LOCAL: CapabilityProfile(CapabilityImpact.MEDIUM),
    Capability.WRITE_LOCAL: CapabilityProfile(CapabilityImpact.HIGH, creates_side_effect=True),
    Capability.NETWORK_READ: CapabilityProfile(CapabilityImpact.MEDIUM),
    Capability.NETWORK_WRITE: CapabilityProfile(CapabilityImpact.HIGH, creates_side_effect=True),
    Capability.EMAIL_SEND: CapabilityProfile(CapabilityImpact.HIGH, creates_side_effect=True),
    Capability.SHELL_EXECUTE: CapabilityProfile(CapabilityImpact.CRITICAL, creates_side_effect=True),
    Capability.CREDENTIAL_ACCESS: CapabilityProfile(
        CapabilityImpact.CRITICAL, accesses_sensitive_data=True
    ),
    Capability.MEMORY_WRITE: CapabilityProfile(CapabilityImpact.MEDIUM, creates_side_effect=True),
    Capability.EXTERNAL_SIDE_EFFECT: CapabilityProfile(
        CapabilityImpact.HIGH, creates_side_effect=True
    ),
}


def capability_profile(capability: Capability) -> CapabilityProfile:
    """Return the security properties for a capability."""
    return CAPABILITY_PROFILES[capability]
