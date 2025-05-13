"""
CLI for autosec library.
Each module will have its own CLI, functions named after module_cli pattern.
"""
import argparse
from autosec import autocred, autolog

def autocred_cli():
	parser = argparse.ArgumentParser(prog='autocred')

	# Main subcommand: 'autocred'
	group = parser.add_mutually_exclusive_group(required=True)

	# adding flags for commands
	group.add_argument('-a', '--add', metavar='CRED', help='Add a new credential')
	group.add_argument('-u', '--update', metavar='CRED', help='Update a credential')
	group.add_argument('-d', '--delete', metavar='CRED', help='Delete a credential')
	group.add_argument('-l', '--list', action='store_true', help='List all credentials')
	group.add_argument('-i', '--init', action='store_true', help='Initialize autocred usage')
	group.add_argument('-val', '--validate', metavar='CRED', help='Validate credential value')

	args = parser.parse_args()

	# Handle the arguments
	if args.add:
		autocred.cli_add(args.add)
	elif args.update:
		autocred.cli_update(args.update)
	elif args.delete:
		autocred.cli_delete(args.delete)
	elif args.list:
		autocred.cli_list()
	elif args.init:
		autocred.cli_init()
	elif args.validate:
		autocred.cli_validate(args.validate)

def autolog_cli():
	parser = argparse.ArgumentParser(prog='autolog')

	# Main subcommand: 'autolog'
	group = parser.add_mutually_exclusive_group(required=True)

	# adding flags for commands
	group.add_argument('-a', '--add', metavar='COLLECTOR', help='Add a new event collector')
	group.add_argument('-d', '--delete', metavar='COLLECTOR', help='Delete an event collector')
	group.add_argument('-u', '--update', metavar='COLLECTOR', help='Update an event collector')
	group.add_argument('-l', '--list', action='store_true', help='List all event collectors')

	args = parser.parse_args()

	# Handle the arguments
	if args.add:
		autolog.cli_add_collector(args.add)
	elif args.delete:
		autolog.cli_delete_collector(args.delete)
	elif args.update:
		autolog.cli_update_collector(args.update)
	elif args.list:
		autolog.cli_list_collectors()

