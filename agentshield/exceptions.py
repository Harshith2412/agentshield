"""AgentShield-specific exceptions."""


class AgentShieldError(Exception):
    """Base class for package errors."""


class DuplicateEventError(AgentShieldError):
    """Raised when an event ID is registered more than once."""


class UnknownParentError(AgentShieldError):
    """Raised when an event refers to an unregistered parent."""
