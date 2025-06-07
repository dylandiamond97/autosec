# autosec
Python package intended to be used in a Security Operations Center for various repeated automation functions. \
Written for Linux. Windows support coming _maybe_. \
Dunno if I want to punish myself that much or not. 

The use cases that spurred development is for log ingestion and/or event collection from disconnected log collectors
which may or may not be separated due to multi-tenant or domain separated SIEM deployments. 

i.e, a centralized app server "secapp1" can send logs to separate collectors which are each allocated to a separate
tenant or client, such that:

Client A SaaS service -> secapp1 collection -> Client A log collector\
Client B SaaS service -> secapp1 collection -> Client B log collector

Additionally, credentials stored on the app server are never visible between clients in plaintext and are easily
referenced in automation scripts.

Client A Plain Credentials (not stored) + socapp1 DEK -> Client A Cipher Credentials (stored)\
Client B Plain Credentials (not stored) + socapp1 DEK -> Cliebt B Cipher Credentials (stored)

Really, I just got tired of manually encrypting API tokens, constantly loading an entire .env file to get access to
those credentials, and then hardcoding different collector info everytime I wanted to send a log, yada yada yada. 

Enough belly aching. Here's my tremendously mediocre README:

# autosec/autocred
Module utilized for local storage of credentials for use in automation scripts.

Use CLI to list, create, update, and delete credentials to be read in scripts. 
CLI must be initialized before use - stores data encryption key in .bashrc, which must be sourced before use.
Encrypted credentials are stored in a .env file in the user's home directory.

example CLI usage:
```bash
autocred -a token_name 
autocred --add token_name
>Value to be encrypted: ******
>One more time for validation: ******

autocred -u token_name
autocred --update token_name
>Updated value: ******
>One more time for validation: ******

autocred -l 
autocred --list
>    token_name = "<ciphertext>"

autocred -d token_name
autocred --delete token_name
```
example call in python script:
```python
from autosec import autocred
some_token = autocred.get_token('token_name')
```
# autosec/autolog
Module utilized for building REST API integrations for on-prem SIEMs/event collectors and automation/script monitoring.

Use CLI to list, create, update, and delete collector configurations to be used in scripts. 

Collector configurations are stored in a JSON file in the user's home directory, and include the IP address and listening port. 
IP is stored as a string and port as an integer to be used with the module. Before a collector is added, a network 
socket connection to the IP and port specified is made to ensure connectivity. 

example CLI usage:
```bash
autolog -a some_collector
autolog --add some_collector
>Please enter some_collector IPv4: <kbd>10.10.10.10</kbd>
>Please enter some_collector port: <kbd>514</kbd>

autolog -l
autolog --list
>some_collector --> 10.10.10.10:514

autolog -u some_collector
autolog --update some_collector
>Please enter some_collector IPv4: <kbd>100.100.100.100</kbd>
>Please enter some_collector port: <kbd>514</kbd>

autolog -l
autolog --list
>some_collector --> 100.100.100.100:514

autolog -d some_collector
autolog --delete some_collector
```

example call in python script:

```python
from autosec import autolog
import requests

collector_IP, collector_port = autolog.set_collector('some_collector')

autolog.enable_exit_report(collector_IP, collector_port)

some_api_response = requests.get(
	url='https://vendor.com/some/api/endpoint',
	headers={"header_key": "header_value"},
	auth=some_token
)

for msg_to_convert in some_api_response['response']:
	leef_log = autolog.json_to_leef(
		json_obj=msg_to_convert,
		vendor='some_vendor',
		product='vendor_product',
		version='1.0',
		event_id='some_event'
	)
	autolog.syslog_to_collector(
		event=leef_log,
		logtype='api_source',
		loglevel='INFO',
		collectorip=collector_IP,
		collectorport=collector_port
	)
```

See also: [Sample Uses](./Sample%20Uses)

This was fun. 