"""Framework-neutral integration failures."""


class FrameworkIntegrationError(RuntimeError):
    pass


class FrameworkUnavailableError(FrameworkIntegrationError):
    pass


class ContextMappingError(FrameworkIntegrationError):
    pass


class ProtectedInvocationError(FrameworkIntegrationError):
    pass
