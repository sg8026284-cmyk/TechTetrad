"""Vulnerable Insecure Deserialization benchmark."""

import yaml


def load_configuration(payload: str):
    # Untrusted YAML configuration payload
    # Dangerous Sink: yaml.load with unsafe Loader
    config = yaml.load(payload, Loader=yaml.Loader)
    return config


if __name__ == "__main__":
    load_configuration("name: test")

