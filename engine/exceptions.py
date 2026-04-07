"""Custom exceptions for the HIPAA Compliance Engine."""


class EngineError(Exception):
    """Base exception for engine errors."""
    pass


class ConfigurationError(EngineError):
    """Raised when configuration is invalid or missing."""
    pass


class CheckError(EngineError):
    """Raised when a compliance check encounters an error."""
    pass


class RegistryError(EngineError):
    """Raised when a control or check module cannot be found."""
    pass


class ScoringError(EngineError):
    """Raised when score calculation fails."""
    pass


class ReportError(EngineError):
    """Raised when report generation fails."""
    pass
