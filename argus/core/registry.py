"""Module registry for discovery and dispatch."""

from typing import Dict, Type, List
from argus.core.base import BaseModule


class Registry:
    """Central registry for all Argus modules."""

    _modules: Dict[str, BaseModule] = {}
    _classes: Dict[str, Type[BaseModule]] = {}

    @classmethod
    def register(cls, module_class: Type[BaseModule]):
        """Register a module class. Instantiates and stores it."""
        instance = module_class()
        cls._modules[instance.name] = instance
        cls._classes[instance.name] = module_class
        return module_class

    @classmethod
    def get(cls, name: str) -> BaseModule:
        return cls._modules.get(name)

    @classmethod
    def all(cls) -> Dict[str, BaseModule]:
        return dict(cls._modules)

    @classmethod
    def names(cls) -> List[str]:
        return sorted(cls._modules.keys())

    @classmethod
    def by_input_type(cls, input_type: str) -> List[BaseModule]:
        """Return modules that accept a given input type."""
        result = []
        for mod in cls._modules.values():
            if mod.input_type == "auto" or mod.input_type == input_type:
                result.append(mod)
        return result


def auto_discover():
    """Import all modules to trigger @Registry.register decorators."""
    import importlib
    modules = [
        "argus.modules.email_recon",
        "argus.modules.username_enum",
        "argus.modules.subdomain_enum",
        "argus.modules.crawler",
        "argus.modules.network_recon",
        "argus.modules.dns_recon",
        "argus.modules.whois_lookup",
        "argus.modules.breach_check",
        "argus.modules.github_recon",
        "argus.modules.phone_recon",
        "argus.modules.ip_geolocation",
        "argus.modules.dork_generator",
        "argus.modules.paste_search",
        "argus.modules.phishing_kit",
    ]
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
        except Exception as e:
            # Module may fail if optional dep not installed
            pass