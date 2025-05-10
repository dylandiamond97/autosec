# autosec
Python package intended to be used in a Security Operations Center for various repeated automation functions. 
Written for Linux. Windows support coming _maybe_. Dunno if I want to punish myself that much or not. 

# autosec/autocred
Module utilized for local storage of credentials for use in automation scripts.

Use CLI to create, update, and delete credentials to be read in scripts. 
CLI must be initialized before use - stores encryption key in .bashrc, which must be sourced before use.
Encrypted credentials are stored in a .env file in the user's home directory.

example call in python script:
```python
from autosec import autocred
some_token = autocred.get_token('token_name')
```
example CLI usage:
```bash
autocred -a token_name 
autocred --add token_name
autocred -u token_name
autocred --update token_name
autocred -d token_name
autocred --delete token_name
```
# autosec/autolog
Module utilized for building REST API integrations for on-prem SIEMs/event collectors and automation/script monitoring.

example call in python script:

```python
from autosec import autolog
import requests

collector_IP = '10.10.10.10'
collector_PORT = 111

autolog.enable_exit_report(collectorip='10.10.10.10', collectorport=514)

some_api_response = requests.get(
	url='https://vendor.com/some/api/endpoint',
	headers={"header_inf": "header_value"},
	auth=some_token
)

for msg in some_api_response['response']:
	log = autolog.json_to_leef(
		json_obj=msg,
		vendor='some_vendor',
		product='vendor_product',
		version='1.0',
		event_id='some_event'
	)
	autolog.syslog_to_collector(
		event=log,
		logtype='api_source',
		loglevel='INFO',
		collectorip=collector_IP,
		collectorport=collector_PORT
	)
```

See also: [Sample Uses](./Sample%20Uses)

This was fun. 