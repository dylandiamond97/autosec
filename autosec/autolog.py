from logging import handlers
import logging
import sys
import traceback
import atexit
import inspect
import os
import time

# print(os.path.abspath(__file__))
# print(inspect.stack())

def enable_exit_report(collectorip, collectorport: int=514):
    """ Function that logs exit state for automation/script to an event collector for monitoring """
    # logs to event collector on clean exit with no unhandled exceptions
    def clean_exit(abs_filepath):
        script = abs_filepath.split("/")[len(abs_filepath.split("/")) - 1]
        leef_header = f"LEEF:1.0|SOC Automation|{abs_filepath}|1.0|Successful Execution|"
        message = f"1 {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime())} SOCAutomationMonitoring {leef_header}scriptName={script}"
        syslog_to_collector(message, 'INFO', collectorip, collectorport)

    # pre-formats message for crash syslog
    def crash_exit_syslog(abs_filepath, frame_leef):
        """Generate generic info before crash"""
        failing_script = abs_filepath.split("/")[len(abs_filepath.split("/")) - 1]
        leef_header = f"LEEF:1.0|SOC Automation|{abs_filepath}|1.0|Unhandled Exception Failure|"
        message = f"1 {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime())} SOCAutomationMonitoring {leef_header}scriptName={failing_script}\t{frame_leef}"
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
        if 'site-packages' not in filename and 'soc_utils' not in filename:
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

