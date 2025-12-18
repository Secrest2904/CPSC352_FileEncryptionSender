import json
import os
from pathlib import Path


class ConfigLoader:
    
    DEFAULT_CONFIG_FILE = 'config.json'
    
    def __init__(self, config_file=None):
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        self.config = {}
        self.load()
    
    def load(self):
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                print(f"✓ Loaded config from {self.config_file}")
            except Exception as e:
                print(f"✗ Error reading config file: {e}")
                self.config = self._get_defaults()
        else:
            print(f"⚠️  Config file not found: {self.config_file}")
            self.config = self._get_defaults()
        
        self._apply_env_overrides()
    
    def _get_defaults(self):
        return {
            "server": {
                "host": "127.0.0.1",
                "port": 5000,
                "debug": False
            },
            "client": {
                "server_host": "127.0.0.1",
                "server_port": 5000
            },
            "crypto": {
                "rsa_key_size": 2048,
                "aes_key_size": 256
            }
        }
    
    def _apply_env_overrides(self):
        env_mappings = {
            'FILE_ENCRYPT_SERVER_HOST': ('server', 'host'),
            'FILE_ENCRYPT_SERVER_PORT': ('server', 'port'),
            'FILE_ENCRYPT_DEBUG': ('server', 'debug'),
            'FILE_ENCRYPT_RSA_KEY_SIZE': ('crypto', 'rsa_key_size'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                try:
                    if key in ['port', 'rsa_key_size', 'aes_key_size']:
                        value = int(value)
                    elif key in ['debug']:
                        value = value.lower() in ['true', '1', 'yes']
                    
                    if section not in self.config:
                        self.config[section] = {}
                    self.config[section][key] = value
                except Exception as e:
                    print(f"⚠️  Error parsing environment variable {env_var}: {e}")
    
    def get(self, section, key, default=None):
        try:
            return self.config.get(section, {}).get(key, default)
        except:
            return default
    
    def get_server_config(self):
        return self.config.get('server', {})
    
    def get_client_config(self):
        return self.config.get('client', {})
    
    def get_crypto_config(self):
        return self.config.get('crypto', {})
    
    def print_config(self):
        print("\n" + "="*70)
        print("  CONFIGURATION")
        print("="*70)
        print(json.dumps(self.config, indent=2))
        print("="*70 + "\n")


_config = None

def get_config(config_file=None):
    global _config
    if _config is None:
        _config = ConfigLoader(config_file)
    return _config