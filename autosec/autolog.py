"""
autosec/autolog.py
Contains functions for logging to an event collector for a SIEM solution. Or not.
No CLI functionality provided yet.
"""

import logging
import sys
import traceback
import atexit
import inspect
import os
import time
import json
import socket
import ipaddress
from pathlib import Path
from logging import handlers

default_config_path = Path.home() / ".autolog_config.json"

def enable_exit_report(collectorip, collectorport: int=514):
	""" Function that logs exit state for automation/script to an event collector for monitoring """
	# logs to event collector on clean exit with no unhandled exceptions
	def clean_exit(abs_filepath):
		script = abs_filepath.split("/")[len(abs_filepath.split("/")) - 1]
		leef_header = f"LEEF:1.0|autosec|{abs_filepath}|1.0|Successful Execution|"
		message = f"1 {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.localtime())} autosec_exit_report {leef_header}scriptName={script}"
		syslog_to_collector(message, 'INFO', collectorip, collectorport)

	# pre-formats message for crash syslog
	def crash_exit_syslog(abs_filepath, frame_leef):
		"""Generate generic info before crash"""
		failing_script = abs_filepath.split("/")[len(abs_filepath.split("/")) - 1]
		leef_header = f"LEEF:1.0|autosec|{abs_filepath}|1.0|Unhandled Exception Failure|"
		message = f"1 {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.localtime())} autosec_exit_report {leef_header}scriptName={failing_script}\t{frame_leef}"
		return message

	# logs to event collector automation crashes caused by unhandled exceptions
	def crash_exit(exc_type, exc_value, exc_tb):
		atexit.unregister(clean_exit)
		trace_lines = traceback.extract_tb(exc_tb)
		tb_summary = []
		for i, frame in enumerate(trace_lines):
			tb_summary.append(f"frame{i}_file={os.path.abspath(frame.filename)}")
			tb_summary.append(f"frame{i}_line={frame.lineno}")
			tb_summary.append(f"frame{i}_func={frame.name}")
			tb_summary.append(f"frame{i}_code={frame.line.strip() if frame.line else 'N/A'}")

		tb_summary.append(f"exc_type={exc_type.__name__}")
		tb_summary.append(f"exc_value={str(exc_value).replace('\t', ' ').replace('\n', ' ')}")

		pre_message = crash_exit_syslog(script_path, script_frame_leef)
		message = f"{pre_message}\t{"\t".join(tb_summary)}"
		syslog_to_collector(message, 'ERROR', collectorip, collectorport)

	script_path = "placeholder"
	stack = inspect.stack()
	for frame in stack:
		filename = frame.filename
		if 'site-packages' not in filename and 'autosec' not in filename:
			script_path = os.path.abspath(filename)
			script_frame_leef = "\t".join(f"{k}={v}" for k, v in frame.__dict__.items())
			break

	sys.excepthook = crash_exit
	atexit.register(clean_exit, script_path)

# function that writes run logs to log files by type, (debug, info, warn) specified in calling script.
def audit_log(logtype, message, collectorip, collectorport):
	log = (f"{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}:\t{logtype}:\t{message}\n")
	syslog_to_collector(log, logtype, collectorip, collectorport)

# function that sends log to SIEM event collector
def syslog_to_collector(event, logtype, collectorip: str, collectorport: int=514, loglevel='INFO'):
	""" Takes an event and syslogs to event collector """
	logger = logging.getLogger(logtype)
	logger.setLevel(loglevel)
	syslog_handler = logging.handlers.SysLogHandler(address=(collectorip, collectorport))
	logger.addHandler(syslog_handler)
	logger.info(event)
	logger.removeHandler(syslog_handler)
	syslog_handler.close()

# function that recursively formats json payloads into LEEF1.0 format
def json_to_leef(json_obj: dict, vendor, product, version, event_id, sep='_'):
	""" Recursive function that takes a JSON payload and flattens to LEEF1.0 """
	def flatten(json_obj: dict, parent_key=''):
		flattened_obj = {}
		for key, value in json_obj.items():
			new_key = f"{parent_key}{sep}{key}" if parent_key else key
			if isinstance(value, dict):
				flattened_obj.update(flatten(value, new_key))
			else:
				flattened_obj[new_key] = value
		return flattened_obj

	flattened = flatten(json_obj)
	key_value_pairs = "\t".join(f"{k}={v}" for k, v in flattened.items())

	leef_header = f"LEEF:1.0|{vendor}|{product}|{version}|{event_id}|"
	return leef_header+key_value_pairs

def is_valid_ip(ip):
	try:
		ipaddress.IPv4Address(ip)
		return True
	except ipaddress.AddressValueError:
		return False

def is_valid_port(port):
	return isinstance(port, int) and 1 <= port <= 65535

def can_connect(ip, port, timeout=3):
	try:
		with socket.create_connection((ip, port), timeout=timeout):
			return True
	except (socket.timeout, ConnectionRefusedError, OSError):
		return False

def unique_collector(collector_info: list, update=None, add=False):
	collectors = load_collector_config(add)
	seen = {key: set() for key in collector_info}

	for collector, net_info in collectors.items():
		print(collector, net_info)
		if collector == update:
			continue
		for info in collector_info:
			print(info)
			val = net_info.get(info)
			print(val)
			if val in seen[info]:
				print(f"Duplicate {info} found for collector {collector}")
				return False
			seen[info].add(val)
			print(seen)
	return True

def load_collector_config(add=False):
	if not add:
		try:
			with open(default_config_path, 'r') as file:
				return json.load(file)
		except FileNotFoundError:
			raise FileNotFoundError("No collector config file found, please run 'autolog --add <collector_name>' from the terminal to add a collector.")
	else:
		try:
			with open(default_config_path, 'r') as file:
				return json.load(file)
		except FileNotFoundError:
			return {}

def add_collector(collector_name):
	collectors = load_collector_config(add=True)
	# Check if collector already exists
	if collectors.get(collector_name):
		print(f"Collector {collector_name} already exists.")
		return False
	# Get IP and port, validate
	ip = input(f"Please enter {collector_name} IPv4: ")
	while not is_valid_ip(ip):
		ip = input(f"Invalid IP, please try again: (q to quit)")
		if ip.casefold() == "q":
			return False

	while True:
		port = input(f"Please enter {collector_name} port: ")
		if port.casefold() == "q":
			exit(1)
		try:
			port = int(port)
			if is_valid_port(port):
				break
			else:
				print("Port must be between 1 and 65535.")
		except ValueError:
			print(f"Enter integer.")

	# Check if can connect
	if not can_connect(ip, port):
		print(f"Unable to connect to {collector_name} at {ip}:{port}, please try again.")
		return False
	elif not unique_collector(['ip', 'port'], add=True):
		print(f"Duplicate IP or port found, please try again.")
		return False
	else:
		collectors[collector_name] = {'ip': ip, 'port': port}
		with open(default_config_path, 'w+') as file:
			json.dump(collectors, file, indent=4)
		return True

def delete_collector(collector_name):
	collectors = load_collector_config()
	collectors.pop(collector_name)
	with open(default_config_path, 'w') as file:
		json.dump(collectors, file, indent=4)
	return True

def update_collector(collector_name):
	collectors = load_collector_config()
	# Check if collector exists
	if not collectors.get(collector_name):
		print(f"Collector {collector_name} does not exist.")
		return False

	# Get IP and port, validate
	ip = input(f"Please enter {collector_name} IPv4: ")
	while not is_valid_ip(ip):
		ip = input(f"Invalid IP, please try again: (q to quit)")
		if ip.casefold() == "q":
			return False
	port = input(f"Please enter {collector_name} port: ")
	while not is_valid_port(port):
		port = input(f"Invalid port, please try again: (q to quit)")
		if port.casefold() == "q":
			return False
		port = int(port)
	# Check if can connect
	if not can_connect(ip, port):
		print(f"Unable to connect to {collector_name} at {ip}:{port}, please try again.")
		return False
	elif not unique_collector(['ip', 'port'], update=collector_name):
		print(f"Duplicate IP or port found for collector {collector_name}, please try again.")
		return False
	else:
		collectors[collector_name] = {'ip': ip, 'port': port}
		with open(default_config_path, 'w') as file:
			json.dump(collectors, file, indent=4)
		return True

def set_collector(collector_name):
	collectors = load_collector_config()
	return collectors[collector_name]['ip'], collectors[collector_name]['port']

def cli_update_collector(collector_name):
	update_collector(collector_name)

def cli_add_collector(collector_name):
	add_collector(collector_name)

def cli_delete_collector(collector_name):
	delete_collector(collector_name)

def cli_list_collectors():
	collectors = load_collector_config()
	for name, collector in collectors.items():
		print(f"{name} --> {collector['ip']}:{collector['port']}")
