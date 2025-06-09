"""
autosec/config.py

"""

import json
import os
from pathlib import Path
from platformdirs import site_config_dir, user_config_dir, PlatformDirs

app_name = 'autosec'
app_auth = 'ddiamo'
dirs = PlatformDirs(app_name, app_auth)

def init_config(user_mode: bool=False):
	base_path = dirs.user_config_dir if user_mode else dirs.site_config_dir
	autolog_conf_path = os.path.join(base_path, "autolog_config.yaml")
	autocred_env_path = os.path.join(base_path, "autocred.env")

	if not os.path.exists(base_path):
		try:
			os.makedirs(base_path, mode=0o750, exist_ok=True)
			print(f"Created config directory at {base_path}")
		except PermissionError:
			print(f"Permission denied. Try running as admin/root.")
			exit(1)

	if not os.path.exists(autolog_conf_path):
		with open(autolog_conf_path, 'w') as f:
			f.write("# Default autosec config\n")
			print(f"Wrote default config at {autolog_conf_path}")
	else:
		print(f"Config already exists at {autolog_conf_path}")

	if not os.path.exists(autocred_env_path):
		with open(autocred_env_path, 'w') as f:
			f.write("# Default autosec config\n")
			print(f"Wrote default config at {autocred_env_path}")
	else:
		print(f"Config already exists at {autocred_env_path}")

	pass

def update_config(user_mode: bool=False):

	pass

def get_autolog_config(user_mode: bool=False):
	base_path = dirs.user_config_dir if user_mode else dirs.site_config_dir
	autolog_conf_path = os.path.join(base_path, "autolog_config.yaml")
	return autolog_conf_path

def get_autocred_env(user_mode: bool=False):
	base_path = dirs.user_config_dir if user_mode else dirs.site_config_dir
	autocred_env_path = os.path.join(base_path, "autocred.env")

	if not os.path.exists(autocred_env_path):
		print(f"env file not found at {autocred_env_path}, validate")
	else:
		return autocred_env_path
