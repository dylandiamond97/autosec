import argparse
from autosec import autocred

def main():
	parser = argparse.ArgumentParser(prog='autosec')
	subparsers = parser.add_subparsers(dest='command', required=True)

	# Subcommand for 'autosec autocred --add <credname>'
	add_parser = subparsers.add_parser('autocred', help='Credential management commands')
	add_subparsers = add_parser.add_subparsers(dest='autocred_command')

	# Add subcommands for 'update', 'add', 'delete', etc.
	add_subparsers.add_parser('update', help='Update credentials')
	add_subparsers.add_parser('add', help='Add new credentials')
	add_subparsers.add_parser('delete', help='Delete credentials')
	add_subparsers.add_parser('list', help='List credentials')
	add_subparsers.add_parser('init', help='Initialize autocred usage')

	args = parser.parse_args()

	# Execute the correct subcommand
	if args.command == 'autocred':
		if args.autocred_command == 'update':
			credname = input('Enter the name of the credential to update: ')
			autocred.cli_update(credname)
		elif args.autocred_command == 'add':
			credname = input('Enter the name of the credential to add: ')
			autocred.cli_add(credname)
		elif args.autocred_command == 'delete':
			credname = input('Enter the name of the credential to delete: ')
			autocred.cli_delete(credname)
		elif args.autocred_command == 'list':
			autocred.cli_list()
		elif args.autocred_command == 'init':
			autocred.cli_init()
	# Add more commands here as needed.

if __name__ == '__main__':
	main()
