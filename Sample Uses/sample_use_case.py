from autosec import autolog
from autosec import autocred
import requests

# set basic info
collector_IP = '10.10.10.10'
collector_PORT = 111

# use autocred to retrieve encrypted creds in decrypted format
some_token = autocred.get_token('token_name')

# use autolog to enable crash/exit reporting
autolog.enable_exit_report(
	collectorip=collector_IP,
	collectorport=collector_PORT
) # port defaults to 514

# make a REST API query to some tool/product/platform
some_api_response = requests.get(
	url='https://vendor.com/some/api/endpoint',
	headers={"header_inf": "header_value"},
	auth=some_token
)

# log REST API response to event collector for on-prem SIEM
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
