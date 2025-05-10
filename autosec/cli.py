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

if __name__ == '__main__':
	autocred_cli()
