"""Per-project config from `.claude/snyk-plugin.json` (REQ-35, 42, 48, 49).

Never raises: a bad file or value falls back to the default and adds a warning.
"""
import json
import os

MODES = ("report", "suggest", "autofix")
SEVERITIES = ("low", "medium", "high", "critical")
DEFAULT_MODE = "report"
DEFAULT_THRESHOLD = "low"
DEFAULT_TIMEOUT = 120
CONFIG_PATH = os.path.join(".claude", "snyk-plugin.json")


class Config(object):
    def __init__(self):
        self.mode = DEFAULT_MODE
        self.severity_threshold = DEFAULT_THRESHOLD
        self.timeout_seconds = DEFAULT_TIMEOUT
        self.file_exists = False
        self.warnings = []


def load(project_dir):
    cfg = Config()
    path = os.path.join(project_dir, CONFIG_PATH)
    if not os.path.lexists(path):
        return cfg
    cfg.file_exists = True
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        cfg.warnings.append("%s is unreadable (%s), using mode report" % (CONFIG_PATH, type(e).__name__))
        return cfg
    if not isinstance(data, dict):
        cfg.warnings.append("%s must contain a JSON object, using mode report" % CONFIG_PATH)
        return cfg

    mode = data.get("mode", DEFAULT_MODE)
    if mode in MODES:
        cfg.mode = mode
    else:
        cfg.warnings.append("unknown mode %r in %s, using report" % (mode, CONFIG_PATH))

    if "severityThreshold" in data:
        t = data["severityThreshold"]
        if t in SEVERITIES:
            cfg.severity_threshold = t
        else:
            cfg.warnings.append("invalid severityThreshold %r in %s, using %s" % (t, CONFIG_PATH, DEFAULT_THRESHOLD))

    if "timeoutSeconds" in data:
        s = data["timeoutSeconds"]
        if isinstance(s, int) and not isinstance(s, bool) and s > 0:
            cfg.timeout_seconds = s
        else:
            cfg.warnings.append("invalid timeoutSeconds %r in %s, using %d" % (s, CONFIG_PATH, DEFAULT_TIMEOUT))
    return cfg
