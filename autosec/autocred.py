import os
import getpass
import time
from cryptography.fernet import Fernet
from pathlib import Path
from dotenv import dotenv_values

home_dir = str(Path.home())
env = Path.home() / ".env"
backup = Path.home() / ".env.bu"
bash_profile = Path.home() / ".bashrc"

def get_key():
	# Check for AutoSec Key
	if "AUTOCRED_KEY" in os.environ:
		return Fernet(os.environ["AUTOCRED_KEY"].encode())
	else:
		raise KeyError("No AUTOCRED_KEY defined in environment variables, run 'autosec autocred --init' in terminal to initialize environment.")

def get_token(cred: str):
	key = get_key()
	conf = dotenv_values(env)
	if cred not in conf:
		raise KeyError(f"Credential '{cred}' not found in .env file.")
	cipher = key.decrypt(conf[cred].encode()).decode()
	return cipher

def add_creds(key: Fernet, conf: dict, cred_name):
	to_write = {}
	while conf.get(cred_name):
		cred_name = input(f"Try again, {cred_name} already exists: (blank to quit)")
		if not cred_name:
			return False

	temp = getpass.getpass(prompt="Value to be encrypted: ")
	validate = getpass.getpass(prompt="One more time for validation: ")
	while temp != validate:
		temp = getpass.getpass(prompt="Didn't match, try again: ")
		validate = getpass.getpass(prompt="One more time for validation: ")

	cipher = key.encrypt(temp.encode()).decode()
	to_write[cred_name] = cipher
	return to_write

def update_creds(user, conf: dict, key: Fernet, cred_name):
	to_write = {}
	while not conf.get(cred_name):
		cred_name = input(f"Try again, {cred_name} does not exist: (blank to quit) ")
		if cred_name.casefold() == "q":
			return False

	temp = getpass.getpass(prompt="Updated password: ")
	validate = getpass.getpass(prompt="One more time for validation: ")
	# cipher = cryptocode.encrypt(temp, key)
	cipher = key.encrypt(temp.encode()).decode()
	while temp != validate:
		temp = getpass.getpass(prompt="Didn't match, try again: ")
		validate = getpass.getpass(prompt="One more time for validation: ")
		cipher = key.encrypt(temp.encode()).decode()
		while cipher == conf[cred_name]:
			temp = getpass.getpass(prompt="Cannot use old password, try again: ")
			validate = getpass.getpass(prompt="One more time for validation: ")
			cipher = key.encrypt(temp.encode()).decode()

	with open(backup, 'a') as file:
		file.write(f"{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}: {user} updated: {cred_name} = \"{conf[cred_name]}\"\n")

	to_write[cred_name] = cipher
	return to_write

def delete_creds(user, conf: dict, cred_name):
	if not conf.get(cred_name):
		return f"{cred_name} does not exist."

	validate = input(f"Please enter credential one more time: ")
	if not cred_name == validate:
		return f"Values do not match."

	with open(backup, 'a') as file:
		file.write(f"{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}: {user} deleted: {cred_name} = \"{conf[cred_name]}\"\n")

	print(f"Deleting {cred_name} credential.")
	del conf[cred_name]
	with open(env, 'w') as file:
		for k in conf:
			file.write(f"{k} = \"{conf[k]}\"\n")
	return True

def set_creds(creds: dict):
	with open(env, 'a') as file:
		for k in creds:
			file.write(f"{k} = \"{creds[k]}\"\n")
			print(f"{k} encrypted and written.")

def cli_add(args):
	key = get_key()
	conf = dotenv_values(env)
	creds = add_creds(key, conf, args)
	if creds:
		set_creds(creds)

def cli_update(args):
	user = os.getlogin()
	key = get_key()
	conf = dotenv_values(env)
	creds = update_creds(user, conf, key, args)
	if creds:
		set_creds(creds)

def cli_delete(args):
	user = os.getlogin()
	conf = dotenv_values(env)
	if delete_creds(user, conf, args):
		print(f"Credential deleted.")

def cli_list():
	conf = dotenv_values(env)
	for var in conf:
		print(f"\t{var} = \"{conf[var]}\"")

def cli_init():
	if "AUTOCRED_KEY" in os.environ:
		return "Environment already initialized."
	else:
		key = Fernet.generate_key().decode()
		with open(bash_profile, 'a') as file:
			file.write(f'\n# AUTOCRED ENC KEY\nexport AUTOCRED_KEY="{key}"\n')
		os.system(f"source {bash_profile}")
	print("autocred initialized successfully.")

