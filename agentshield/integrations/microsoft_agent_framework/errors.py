from agentshield.integrations.base.errors import FrameworkIntegrationError, FrameworkUnavailableError


class MicrosoftAgentFrameworkError(FrameworkIntegrationError):
    pass


class MicrosoftAgentFrameworkUnavailableError(FrameworkUnavailableError):
    pass
