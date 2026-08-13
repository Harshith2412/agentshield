"""Safe LangGraph integration errors."""


class LangGraphIntegrationError(RuntimeError):
    pass


class LangGraphUnavailableError(LangGraphIntegrationError):
    pass


class StateBridgeError(LangGraphIntegrationError):
    pass


class ToolMappingError(LangGraphIntegrationError):
    pass
