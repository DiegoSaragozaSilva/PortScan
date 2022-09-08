class ExceptionType:
    INVALID_ARGUMENT = "Invalid Argument"
    INVALID_PATTERN = "Invalid Pattern"
    MISSING_ARGUMENT = "Missing Argument"

class LogType:
    GLOBAL = "GLOBAL"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    INFO = "INFO"
    ERROR = "ERROR"

_debugColors = {
    "GLOBAL": "\u001b[0m",
    "SUCCESS": "\u001b[32m",
    "WARNING": "\u001b[33m",
    "INFO": "\u001b[36m",
    "ERROR": "\u001b[31m"
}

def debugLog(logType, message):
    globalColor = _debugColors[LogType.GLOBAL]
    color = _debugColors[logType]
    print(f"[{color}{logType}{globalColor}]: {message}")
