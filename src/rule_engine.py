import os
import yaml

def load_rules(filepath=None):
    if filepath is None:
        # Load rules.yaml from the same folder as this file
        filepath = os.path.join(os.path.dirname(__file__), "rules.yaml")
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)['rules']


def match_rule(proc_name, rules):
    for rule in rules:
        if proc_name.lower() in [p.lower() for p in rule.get("process_name", [])]:
            return rule
    return None
