"""
Base addon class for mitmproxy plugins.
All addons should inherit from this class.
"""
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class BaseAddon(ABC):
    """Abstract base class for mitmproxy addons."""
    
    # Plugin metadata - override in subclasses
    name: str = "base_addon"
    description: str = "Base addon"
    version: str = "1.0.0"
    
    def __init__(self):
        self.enabled = False
        self.config = {}
    
    @abstractmethod
    def load(self, loader):
        """
        Called by mitmproxy when the addon is loaded.
        Use this hook for initialization/logging only.
        Registration is handled by the addon manager.
        """
        pass
    
    @abstractmethod
    def configure(self, options):
        """
        Called when mitmproxy options are configured.
        """
        pass
    
    def enable(self):
        """Enable this addon."""
        self.enabled = True
        logger.info(f"Addon {self.name} enabled")
    
    def disable(self):
        """Disable this addon."""
        self.enabled = False
        logger.info(f"Addon {self.name} disabled")
    
    def get_config(self, key, default=None):
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set_config(self, key, value):
        """Set configuration value."""
        self.config[key] = value
    
    def to_dict(self):
        """Return addon metadata as dict."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "config": self.config
        }
