import os
import yaml

def load_rules(filepath=None):
    if filepath is None:
        filepath = os.path.join(os.path.dirname(__file__), "rules.yaml")
    with open(filepath, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("rules.yaml must contain a top-level 'rules:' list")
    return rules


def _norm(s):
    if s is None:
        return ""
    return str(s).lower()


def _list_norm(values):
    if not values:
        return []
    return [_norm(v) for v in values if v is not None]


def _match_any_equal(value, candidates):
    """Case-insensitive equality match against a list."""
    v = _norm(value)
    for c in _list_norm(candidates):
        if v == c:
            return True
    return False


def _match_any_contains(text, substrings):
    """Case-insensitive substring match against a list."""
    t = _norm(text)
    for sub in _list_norm(substrings):
        if sub and sub in t:
            return True
    return False


def match_rule(proc_info, rules):
    """
    proc_info is a dict like:
      {
        "name": "python.exe",
        "cmdline": "python.exe ...",
        "parent_name": "powershell.exe",
      }
    Returns the first matched rule, or None.
    """
    name = proc_info.get("name", "")
    cmdline = proc_info.get("cmdline", "")
    parent_name = proc_info.get("parent_name", "")

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        # Conditions: treat missing condition sets as "no constraint"
        pn = rule.get("process_name", [])
        cn = rule.get("cmdline_contains", [])
        par = rule.get("parent_name", [])

        if pn and not _match_any_equal(name, pn):
            continue
        if cn and not _match_any_contains(cmdline, cn):
            continue
        if par and not _match_any_equal(parent_name, par):
            continue

        # Matched all provided constraints
        if "severity" not in rule:
            rule["severity"] = "medium"
        if "response" not in rule:
            rule["response"] = {}
        return rule

    return None
