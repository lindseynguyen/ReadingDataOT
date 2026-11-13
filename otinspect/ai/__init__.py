"""Optional AI assistance through an internal / self-hosted model (off until a profile is configured).

Nothing here runs during a normal scan. The scan itself stays offline; only an explicit AI
request contacts the endpoint configured in the profile, with pseudonymised data.
"""
from .analysis import LANGUAGES, TASKS, AIAnswer, analyse, prepare, send
from .client import AIRequestError, ChatClient
from .config import (PROVIDERS, AIConfigError, AIProfile, check_endpoint, get_api_key, get_profile,
                     keyring_available, load_profiles, save_profiles, set_api_key)
from .context import load_report

__all__ = ["LANGUAGES", "TASKS", "PROVIDERS", "AIAnswer", "AIConfigError", "AIProfile", "AIRequestError",
           "ChatClient", "analyse", "prepare", "send", "check_endpoint", "get_api_key", "get_profile",
           "keyring_available", "load_profiles", "save_profiles", "set_api_key", "load_report"]
