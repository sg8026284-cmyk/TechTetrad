"""Safe Deserialization benchmark (yaml.safe_load)."""

import yaml


def load_configuration(payload: str):
    # Safe: using yaml.safe_load which prevents arbitrary object instantiation
    config = yaml.safe_load(payload)
    return config


if __name__ == "__main__":
    pass

