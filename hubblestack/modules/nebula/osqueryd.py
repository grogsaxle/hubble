# -*- coding: utf-8 -*-
"""
osquery wrapper for HubbleStack Nebula

Designed to run sets of osquery queries defined in pillar. These sets will have
a unique identifier, and be targeted by identifier. Usually, this identifier
will be a frequency. ('15 minutes', '1 day', etc). Identifiers are
case-insensitive.

You can then use the scheduler of your choice to run sets os queries at
whatever frequency you choose.

Sample pillar data:

nebula_osquery:
  hour:
    - crontab: query: select c.*,t.iso_8601 as _time from crontab as c join time as t;
    - query_name: suid_binaries
      query: select sb.*, t.iso_8601 as _time from suid_bin as sb join time as t;
  day:
    - query_name: rpm_packages
      query: select rpm.*, t.iso_8601 from rpm_packages as rpm join time as t;
"""


import glob
import json
import logging
import os
import time
import hashlib
import yaml
import zlib
from inspect import getfullargspec

import hubblestack.utils.files
import hubblestack.utils.platform

from hubblestack.exceptions import CommandExecutionError
from hubblestack import __version__
import hubblestack.log

from hubblestack.modules.nebula.helper import dict_update, get_top_data

from hubblestack.status import HubbleStatus

log = logging.getLogger(__name__)

CRC_BYTES = 256
hubble_status = HubbleStatus(__name__, "top", "queries", "osqueryd_monitor", "osqueryd_log_parser")

__RESULT_LOG_OFFSET__ = {}
OSQUERYD_NEEDS_RESTART = False
IS_FIPS_ENABLED = True if "usedforsecurity" in getfullargspec(hashlib.new).kwonlyargs else False

@hubble_status.watch
def osqueryd_monitor(
    configfile=None,
    conftopfile=None,
    flagstopfile=None,
    flagfile=None,
    logdir=None,
    databasepath=None,
    pidfile=None,
    hashfile=None,
):
    """
    This function will monitor whether osqueryd is running on the system or not.
    Whenever it detects that osqueryd is not running, it will start the osqueryd.
    Also, it checks for conditions that would require osqueryd to restart
    (such as changes in flag file content). On such conditions, osqueryd will get restarted,
    thereby loading new files.

    configfile
        Path to osquery configuration file. If this is specified, conftopfile will be ignored

    conftopfile
        Path to topfile which will be used to dynamically generate osquery conf in JSON format

    flagstopfile
        Path to topfile which will be used to dynamically generate osquery flags

    flagfile
        Path to osquery flag file. If this is specified, flagstopfile will be ignored

    logdir
        Path to log directory where osquery daemon/service will write logs

    pidfile
        pidfile path where osquery daemon will write pid info

    hashfile
        path to hashfile where osquery flagfile's hash would be stored

    daemonize
        daemonize osquery daemon. Default is True. Applicable for posix system only

    """
    log.info("Starting osqueryd monitor")
    saltenv = __mods__["config.get"]("hubblestack:nova:saltenv", "base")
    log.debug("Cached nebula files to cachedir")
    cachedir = os.path.join(__opts__.get("cachedir"), "files", saltenv, "hubblestack_nebula_v2")
    base_path = cachedir
    servicename = "hubble_osqueryd"
    # sanity check each file and if not present assign a new value
    logdir = logdir or __opts__.get("osquerylogpath")
    databasepath = databasepath or __opts__.get("osquery_dbpath")
    pidfile = pidfile or os.path.join(base_path, "hubble_osqueryd.pidfile")
    hashfile = hashfile or os.path.join(base_path, "hash_of_flagfile.txt")
    if hubblestack.utils.platform.is_windows():
        conftopfile = conftopfile or "salt://hubblestack_nebula_v2/win_top.osqueryconf"
        flagstopfile = flagstopfile or "salt://hubblestack_nebula_v2/win_top.osqueryflags"

        osqueryd_running = _osqueryd_running_status_windows(servicename)
    else:
        conftopfile = conftopfile or "salt://hubblestack_nebula_v2/top.osqueryconf"
        flagstopfile = flagstopfile or "salt://hubblestack_nebula_v2/top.osqueryflags"

        osqueryd_running = _osqueryd_running_status(pidfile)

    configfile = configfile or _generate_osquery_conf_file(conftopfile)
    flagfile = flagfile or _generate_osquery_flags_file(flagstopfile)
    if not osqueryd_running:
        _start_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, servicename)
    else:
        osqueryd_restart = _osqueryd_restart_required(hashfile, flagfile)
        if osqueryd_restart:
            _restart_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, hashfile, servicename)


@hubble_status.watch
def osqueryd_log_parser(
    osqueryd_logdir=None,
    backuplogdir=None,
    maxlogfilesizethreshold=None,
    logfilethresholdinbytes=None,
    backuplogfilescount=None,
    enablediskstatslogging=False,
    topfile_for_mask=None,
    mask_passwords=False,
):
    """
    Parse osquery daemon logs and perform log rotation based on specified parameters

    osqueryd_logdir
        Directory path where osquery result and snapshot logs would be created

    backuplogdir
        Directory path where hubble should create log file backups post log rotation

    maxlogfilesizethreshold
        Log file size threshold in bytes. If osquery log file size is greter than this value,
        then logs will only be roatated but not parsed

    logfilethresholdinbytes
        Log file size threshold in bytes. If osquery log file is greter than this value,
        then log rotation will be done once logs have been processed

    backuplogfilescount
        Number of log file backups to keep

    enablediskstatslogging
        Enable logging of disk usage of /var/log partition. Default is False

    topfile_for_mask
        This is the location of the top file from which the masking information
        will be extracted

    mask_passwords
        Defaults to False. If set to True, passwords mentioned in the
        return object are masked

    """
    ret = []
    if not osqueryd_logdir:
        osqueryd_logdir = __opts__.get("osquerylogpath")
    result_logfile = os.path.normpath(os.path.join(osqueryd_logdir, "osqueryd.results.log"))
    snapshot_logfile = os.path.normpath(os.path.join(osqueryd_logdir, "osqueryd.snapshots.log"))

    log.debug("Result log file resolved to: %s", result_logfile)
    log.debug("Snapshot log file resolved to: %s", snapshot_logfile)

    backuplogdir = backuplogdir or __opts__.get("osquerylog_backupdir")
    logfilethresholdinbytes = logfilethresholdinbytes or __opts__.get("osquery_logfile_maxbytes")
    maxlogfilesizethreshold = maxlogfilesizethreshold or __opts__.get("osquery_logfile_maxbytes_toparse")
    backuplogfilescount = backuplogfilescount or __opts__.get("osquery_backuplogs_count")

    if os.path.exists(result_logfile):
        logfile_offset = _get_file_offset(result_logfile)
        event_data = _parse_log(
            result_logfile,
            logfile_offset,
            backuplogdir,
            logfilethresholdinbytes,
            maxlogfilesizethreshold,
            backuplogfilescount,
            enablediskstatslogging,
        )
        if event_data:
            ret += event_data
    else:
        log.warn("Specified osquery result log file doesn't exist: %s", result_logfile)

    if os.path.exists(snapshot_logfile):
        logfile_offset = _get_file_offset(snapshot_logfile)
        event_data = _parse_log(
            snapshot_logfile,
            logfile_offset,
            backuplogdir,
            logfilethresholdinbytes,
            maxlogfilesizethreshold,
            backuplogfilescount,
            enablediskstatslogging,
        )
        if event_data:
            ret += event_data
    else:
        log.warn("Specified osquery snapshot log file doesn't exist: %s", snapshot_logfile)

    ret = _update_event_data(ret)

    if mask_passwords:
        log.info("Perform masking")
        _mask_object(ret, topfile_for_mask)
    return ret


def _update_event_data(ret):
    """
    Helper function that goes over the event_data in ret and updates the objects with 'snapshot and
    'column' action that have __JSONIFY__.
    Returns the updated ret.
    """
    # sanity check
    if not ret:
        return ret

    n_ret = []
    for event_data in ret:
        obj = json.loads(event_data)
        if "action" in obj and obj["action"] == "snapshot":
            for result in obj["snapshot"]:
                for key, value in result.items():
                    if value and isinstance(value, str) and value.startswith("__JSONIFY__"):
                        result[key] = json.loads(value[len("__JSONIFY__") :])
        elif "action" in obj:
            for key, value in obj["columns"].items():
                if value and isinstance(value, str) and value.startswith("__JSONIFY__"):
                    obj["columns"][key] = json.loads(value[len("__JSONIFY__") :])
        n_ret.append(obj)

    return n_ret


def check_disk_usage(path=None):
    """
    Check disk usage of specified path.
    If no path is specified, path will default to '/var/log'

    Can be scheduled via hubble conf as well

    *** Linux Only method ***

    path
        Defaults to '/var/log'

    """
    disk_stats = {}
    if hubblestack.utils.platform.is_windows():
        log.info("Platform is windows, skipping disk usage stats")
        disk_stats = {"Error": "Platform is windows"}
    else:
        if not path:
            # We would be interested in var partition disk stats only,
            # for other partitions specify 'path' param
            path = "/var/log"
        df_stat = os.statvfs(path)
        total = df_stat.f_frsize * df_stat.f_blocks
        avail = df_stat.f_frsize * df_stat.f_bavail
        used = total - avail
        per_used = float(used) / total * 100
        log.info(
            "Stats for path: %s, Total: %f, Available: %f, Used: %f, Used %%: %f", path, total, avail, used, per_used
        )
        disk_stats = {"total": total, "available": avail, "used": used, "use_percent": per_used, "path": path}

        if __mods__["config.get"]("splunklogging", False):
            log.debug("Logging disk usage stats to splunk")
            stats = {"disk_stats": disk_stats, "schedule_time": time.time()}
            hubblestack.log.emit_to_splunk(stats, "INFO", "hubblestack.disk_usage")

    return disk_stats


@hubble_status.watch
def _generate_osquery_conf_file(conftopfile):
    """
    Function to dynamically create osquery configuration file in JSON format.
    This function would load osquery configuration in YAML format and
    make use of topfile to selectively load file(s) based on grains
    """

    log.info("Generating osquery conf file using topfile: %s", conftopfile)
    saltenv = __mods__["config.get"]("hubblestack:nova:saltenv", "base")
    log.debug("Cached nebula files to cachedir")
    cachedir = os.path.join(__opts__.get("cachedir"), "files", saltenv, "hubblestack_nebula_v2")
    base_path = cachedir

    osqd_configs = get_top_data(conftopfile)
    configfile = os.path.join(base_path, "osquery.conf")
    conf_data = {}
    osqd_configs = ["salt://hubblestack_nebula_v2/" + config.replace(".", "/") + ".yaml" for config in osqd_configs]
    for osqd_conf in osqd_configs:
        if "salt://" in osqd_conf:
            orig_fh = osqd_conf
            osqd_conf = __mods__["cp.cache_file"](osqd_conf)
        if not osqd_conf:
            log.error("Could not find file %s.", orig_fh)
            return None
        if os.path.isfile(osqd_conf):
            with open(osqd_conf, "r") as yfile:
                f_data = yaml.safe_load(yfile)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError("File data is not formed as a dict {0}".format(f_data))
                conf_data = dict_update(conf_data, f_data, recursive_update=True, merge_lists=True)
    if conf_data:
        try:
            log.debug("Writing config to osquery.conf file")
            with open(configfile, "w") as conf_file:
                json.dump(conf_data, conf_file)
        except Exception:
            log.error("Failed to generate osquery conf file using topfile.", exc_info=True)

    return configfile


def _generate_osquery_flags_file(flagstopfile):
    """
    Function to dynamically create osquery flags file.
    This function would load osquery flags in YAML format and
    make use of topfile to selectively load file(s) based on grains
    """

    log.info("Generating osquery flags file using topfile: %s", flagstopfile)
    saltenv = __mods__["config.get"]("hubblestack:nova:saltenv", "base")
    log.debug("Cached nebula files to cachedir")
    cachedir = os.path.join(__opts__.get("cachedir"), "files", saltenv, "hubblestack_nebula_v2")
    base_path = cachedir

    osqd_flags = get_top_data(flagstopfile)
    flagfile = os.path.join(base_path, "osquery.flags")
    flags_data = {}
    osqd_flags = ["salt://hubblestack_nebula_v2/" + config.replace(".", "/") + ".yaml" for config in osqd_flags]
    for out_file in osqd_flags:
        if "salt://" in out_file:
            orig_fh = out_file
            out_file = __mods__["cp.cache_file"](out_file)
        if not out_file:
            log.error("Could not find file %s.", orig_fh)
            return None
        if os.path.isfile(out_file):
            with open(out_file, "r") as yfile:
                f_data = yaml.safe_load(yfile)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError("File data is not formed as a dict {0}".format(f_data))
                flags_data = dict_update(flags_data, f_data, recursive_update=True, merge_lists=True)
    if flags_data:
        try:
            log.debug("Writing config to osquery.flags file")
            with open(flagfile, "w") as prop_file:
                for key in flags_data:
                    propdata = "--" + key + "=" + flags_data.get(key) + "\n"
                    prop_file.write(propdata)
        except Exception:
            log.error("Failed to generate osquery flags file using topfile.", exc_info=True)

    return flagfile


def _osqueryd_running_status(pidfile):
    """
    This function will check whether osqueryd is running in *nix systems
    """
    log.info("checking if osqueryd is already running or not")
    osqueryd_running = False
    if os.path.isfile(pidfile):
        try:
            with open(pidfile, "r") as pfile:
                xpid = pfile.readline().strip()
                try:
                    xpid = int(xpid)
                except Exception:
                    xpid = 0
                    log.warn('unable to parse pid="%d" in pidfile=%s', xpid, pidfile)
                if xpid:
                    log.info("pidfile=%s exists and contains pid=%d", pidfile, xpid)
                    if os.path.isdir("/proc/{pid}".format(pid=xpid)):
                        try:
                            with open("/proc/{pid}/cmdline".format(pid=xpid), "r") as cmd_file:
                                cmdline = cmd_file.readline().strip().strip("\x00").replace("\x00", " ")
                                if "osqueryd" in cmdline:
                                    log.info("process folder present and process is osqueryd")
                                    osqueryd_running = True
                                else:
                                    log.error("process is not osqueryd," " attempting to start osqueryd")
                        except Exception:
                            log.error("process's cmdline cannot be determined," " attempting to start osqueryd")
                    else:
                        log.error("process folder not present, attempting to start osqueryd")
                else:
                    log.error("pid cannot be determined, attempting to start osqueryd")
        except Exception:
            log.error("unable to open pidfile, attempting to start osqueryd")
    else:
        cmd = ["pkill", "hubble_osqueryd"]
        __mods__["cmd.run"](cmd, timeout=600)
        log.error("pidfile not found, attempting to start osqueryd")
    return osqueryd_running


def _osqueryd_restart_required(hashfile, flagfile):
    """
    This function will check whether osqueryd needs to be restarted
    """
    global OSQUERYD_NEEDS_RESTART
    log.info("checking if osqueryd needs to be restarted or not")
    if OSQUERYD_NEEDS_RESTART:
        OSQUERYD_NEEDS_RESTART = False
        return True
    try:
        with open(flagfile, "r") as open_file:
            file_content = open_file.read().lower().rstrip("\n\r ").strip("\n\r")
            if IS_FIPS_ENABLED:
                hash_md5 = hashlib.md5(usedforsecurity=False)
            else:
                hash_md5 = hashlib.md5()
            hash_md5.update(file_content.encode("ISO-8859-1"))
            new_hash = hash_md5.hexdigest()

        if not os.path.isfile(hashfile):
            with open(hashfile, "w") as hfile:
                hfile.write(new_hash)
                return False
        else:
            with open(hashfile, "r") as hfile:
                old_hash = hfile.read()
                if old_hash != new_hash:
                    log.info("old hash is %s and new hash is %s", old_hash, new_hash)
                    log.info("changes detected in flag file")
                    return True
                else:
                    log.info("no changes detected in flag file")
    except Exception:
        log.error(
            "some error occured, unable to determine whether osqueryd need to be restarted," " not restarting osqueryd"
        )
    return False

def _osqueryd_running_status_windows(servicename):
    """
    This function will check whether osqueryd is running in windows systems
    """
    log.info("checking if osqueryd is already running or not")
    osqueryd_running = False
    cmd_status = "(Get-Service -Name " + servicename + ").Status"
    osqueryd_status = __mods__["cmd.run"](cmd_status, shell="powershell")
    if osqueryd_status == "Running":
        osqueryd_running = True
        log.info("osqueryd already running")
    else:
        log.info("osqueryd not running")
        osqueryd_running = False

    return osqueryd_running

# KEEP
def _start_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, servicename):
    """
    This function will start osqueryd
    """
    log.info("osqueryd is not running, attempting to start osqueryd")
    if hubblestack.utils.platform.is_windows():
        log.info("requesting service manager to start osqueryd")
        cmd = ["net", "start", servicename]
    else:
        cmd = [
            "/opt/osquery/hubble_osqueryd",
            "--pidfile={0}".format(pidfile),
            "--logger_path={0}".format(logdir),
            "--config_path={0}".format(configfile),
            "--flagfile={0}".format(flagfile),
            "--database_path={0}".format(databasepath),
            "--daemonize",
        ]
    ret_dict = __mods__["cmd.run_all"](cmd, timeout=600)
    if ret_dict.get("retcode", None) != 0:
        log.error(
            "Failed to start osquery daemon. Retcode: %s and error: %s",
            ret_dict.get("retcode", None),
            ret_dict.get("stderr", None),
        )
    else:
        log.info("Successfully started osqueryd")


def _restart_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, hashfile, servicename):
    """
    This function will restart osqueryd
    """
    log.info("osqueryd needs to be restarted, restarting now")

    with open(flagfile, "r") as open_file:
        file_content = open_file.read().lower().rstrip("\n\r ").strip("\n\r")
        if IS_FIPS_ENABLED:
            hash_md5 = hashlib.md5(usedforsecurity=False)
        else:
            hash_md5 = hashlib.md5()
        hash_md5.update(file_content.encode("ISO-8859-1"))
        new_hash = hash_md5.hexdigest()

    with open(hashfile, "w") as hfile:
        hfile.write(new_hash)
    _stop_osqueryd(servicename, pidfile)
    _start_osqueryd(
        pidfile=pidfile,
        configfile=configfile,
        flagfile=flagfile,
        logdir=logdir,
        databasepath=databasepath,
        servicename=servicename,
    )


def _stop_osqueryd(servicename, pidfile):
    """
    Thid function will stop osqueryd.
    """
    if hubblestack.utils.platform.is_windows():
        stop_cmd = ["net", "stop", servicename]
    else:
        stop_cmd = ["pkill", "hubble_osqueryd"]
    ret_stop = __mods__["cmd.run_all"](stop_cmd, timeout=600)
    if ret_stop.get("retcode", None) != 0:
        log.error(
            "Failed to stop osqueryd. Retcode: %s and error: %s",
            ret_stop.get("retcode", None),
            ret_stop.get("stderr", None),
        )
    else:
        log.info("Successfully stopped osqueryd")
    if not hubblestack.utils.platform.is_windows():
        remove_pidfile_cmd = ["rm", "-rf", "{0}".format(pidfile)]
        __mods__["cmd.run"](remove_pidfile_cmd, timeout=600)


def _parse_log(
    path_to_logfile,
    offset,
    backuplogdir,
    logfilethresholdinbytes,
    maxlogfilesizethreshold,
    backuplogfilescount,
    enablediskstatslogging,
):
    """
    Parse logs generated by osquery daemon.
    Path to log file to be parsed should be specified
    """
    event_data = []
    file_offset = offset
    rotate_log = False
    if os.path.exists(path_to_logfile):
        with open(path_to_logfile, "r") as file_des:
            if file_des:
                if os.stat(path_to_logfile).st_size > maxlogfilesizethreshold:
                    # This is done to handle scenarios where hubble process was in stopped state and
                    # osquery daemon was generating logs for that time frame.
                    # When hubble is started and this function gets executed,
                    # it might be possible that the log file is now huge.
                    # In this scenario hubble might take too much time to process the logs
                    # which may not be required
                    # To handle this, log file size is validated against max threshold size.
                    log.info("Log file size is above max threshold size that can be parsed by Hubble.")
                    log.info(
                        "Log file size: %f, max threshold: %f",
                        os.stat(path_to_logfile).st_size,
                        maxlogfilesizethreshold,
                    )
                    log.info("Rotating log and skipping parsing for this iteration")
                    # Closing explicitly to handle File in Use exception in windows
                    file_des.close()
                    _perform_log_rotation(
                        path_to_logfile, file_offset, backuplogdir, backuplogfilescount, enablediskstatslogging, False
                    )
                    # Reset file offset to start of file in case original file is rotated
                    file_offset = 0
                else:
                    if os.stat(path_to_logfile).st_size > logfilethresholdinbytes:
                        rotate_log = True
                    file_des.seek(offset)
                    for event in file_des.readlines():
                        event_data.append(event)
                    file_offset = file_des.tell()
                    # Closing explicitly to handle File in Use exception in windows
                    file_des.close()
                    if rotate_log:
                        log.info("Log file size above threshold, " "going to rotate log file: %s", path_to_logfile)
                        residue_events = _perform_log_rotation(
                            path_to_logfile,
                            file_offset,
                            backuplogdir,
                            backuplogfilescount,
                            enablediskstatslogging,
                            True,
                        )
                        if residue_events:
                            log.info("Found few residue logs, updating the data object")
                            event_data += residue_events
                        # Reset file offset to start of file in case original file is rotated
                        file_offset = 0
                _set_cache_offset(path_to_logfile, file_offset)
            else:
                log.error("Unable to open log file for reading: %s", path_to_logfile)
    else:
        log.error("Log file doesn't exists: %s", path_to_logfile)

    return event_data


def _set_cache_offset(path_to_logfile, offset):
    """
    Cache file offset in specified file
    A file will be created in cache directory and following attributes will be stored in it
    offset, initial_crc (CRC for first 256 bytes of log file), last_crc (CRC for last 256 bytes of log file)
    """
    try:
        log_filename = os.path.basename(path_to_logfile)
        offsetfile = os.path.join(__opts__.get("cachedir"), "osqueryd", "offset", log_filename)
        log_file_initial_crc = 0
        log_file_last_crc = 0
        if offset > 0:
            with open(path_to_logfile, "rb") as log_file:
                log_file.seek(0)
                log_file_initial_crc = zlib.crc32(log_file.read(CRC_BYTES))

            if offset > CRC_BYTES:
                with open(path_to_logfile, "rb") as log_file:
                    log_file.seek(offset - CRC_BYTES)
                    log_file_last_crc = zlib.crc32(log_file.read(CRC_BYTES))

        offset_dict = {"offset": offset, "initial_crc": log_file_initial_crc, "last_crc": log_file_last_crc}
        log.info(
            "Storing following information for file {0}. Offset: {1}, Initial_CRC: {2}, Last_CRC: {3}".format(
                path_to_logfile, offset, log_file_initial_crc, log_file_last_crc
            )
        )
        if not os.path.exists(os.path.dirname(offsetfile)):
            os.makedirs(os.path.dirname(offsetfile))

        with open(offsetfile, "w") as json_file:
            json.dump(offset_dict, json_file)
    except Exception as e:
        log.error("Exception in creating offset file", exc_info=1)


def _get_file_offset(path_to_logfile):
    """
    Fetch file offset for specified file
    """
    offset = 0
    try:
        log_filename = os.path.basename(path_to_logfile)
        offsetfile = os.path.join(__opts__.get("cachedir"), "osqueryd", "offset", log_filename)
        if not os.path.isfile(offsetfile):
            log.info("Offset file: {0} does not exist. Returning offset as 0.".format(offsetfile))
        else:
            with open(offsetfile, "r") as file:
                offset_data = json.load(file)
            offset = offset_data.get("offset")
            initial_crc = offset_data.get("initial_crc")
            last_crc = offset_data.get("last_crc")
            log.debug(
                "Offset file: {0} exist. Got following values: offset: {1}, initial_crc: {2}, last_crc: {3}".format(
                    offsetfile, offset, initial_crc, last_crc
                )
            )

            log_file_offset = 0
            log_file_initial_crc = 0
            with open(path_to_logfile, "rb") as log_file:
                log_file.seek(log_file_offset)
                log_file_initial_crc = zlib.crc32(log_file.read(CRC_BYTES))

            if log_file_initial_crc == initial_crc:
                log.debug(
                    "Initial CRC for log file {0} matches. Now matching last CRC for the given offset {1}".format(
                        path_to_logfile, offset
                    )
                )
                if offset > CRC_BYTES:
                    log_file_offset = offset - CRC_BYTES
                    log_file_last_crc = 0
                    with open(path_to_logfile, "rb") as log_file:
                        log_file.seek(log_file_offset)
                        log_file_last_crc = zlib.crc32(log_file.read(CRC_BYTES))
                    if log_file_last_crc == last_crc:
                        log.info(
                            "Last CRC for log file {0} matches. Returning the offset value {1}".format(
                                path_to_logfile, offset
                            )
                        )
                    else:
                        log.error(
                            "Last CRC for log file {0} does not match. Got values: Expected: {1}, Actual: {2}. Returning offset as 0.".format(
                                path_to_logfile, last_crc, log_file_last_crc
                            )
                        )
                        offset = 0
                else:
                    log.info(
                        "Last offset of log file {0} is less than {1}. Returning 0.".format(path_to_logfile, CRC_BYTES)
                    )
                    offset = 0
            else:
                log.error(
                    "Initial CRC for log file {0} does not match. Got values: Expected: {1}, Actual {2}. Returning offset as 0.".format(
                        path_to_logfile, initial_crc, log_file_initial_crc
                    )
                )
                offset = 0
    except Exception as e:
        log.error(
            "Exception in getting offset for file: %s. Returning offset as 0. Exception", path_to_logfile, exc_info=1
        )
        offset = 0
    return offset


def _perform_log_rotation(
    path_to_logfile, offset, backup_log_dir, backup_log_files_count, enable_disk_stats_logging, read_residue_events
):
    """
    Perform log rotation on specified file and create backup of file under
    specified backup directory.
    """
    residue_events = []
    if os.path.exists(path_to_logfile):
        log_filename = os.path.basename(path_to_logfile)
        if os.path.exists(backup_log_dir):
            list_of_backup_log_files = glob.glob(os.path.normpath(os.path.join(backup_log_dir, log_filename)) + "*")

            if list_of_backup_log_files:
                log.info(
                    "Backup log file count: %d and backup count threshold: %d",
                    len(list_of_backup_log_files),
                    backup_log_files_count,
                )
                list_of_backup_log_files.sort()
                log.info("Backup log file sorted list: %s", list_of_backup_log_files)
                if len(list_of_backup_log_files) >= backup_log_files_count:
                    list_of_backup_log_files = list_of_backup_log_files[
                        : len(list_of_backup_log_files) - backup_log_files_count + 1
                    ]
                    for dfile in list_of_backup_log_files:
                        hubblestack.utils.files.remove(dfile)
                    log.info("Successfully deleted extra backup log files")

            residue_events = []
            log_filename = os.path.basename(path_to_logfile)

            backup_log_file = os.path.normpath(os.path.join(backup_log_dir, log_filename) + "-" + str(time.time()))
            hubblestack.utils.files.rename(path_to_logfile, backup_log_file)

            if read_residue_events:
                residue_events = _read_residue_logs(backup_log_file, offset)

            if enable_disk_stats_logging:
                # As of now, this method would send disk stats to Splunk (if configured)
                _disk_stats = check_disk_usage()
        else:
            log.error("Specified backup log directory does not exists." " Log rotation will not be performed.")

    return residue_events


def _read_residue_logs(path_to_logfile, offset):
    """
    Read any logs that might have been written while creating backup log file
    """
    event_data = []
    if os.path.exists(path_to_logfile):
        with open(path_to_logfile, "r") as file_des:
            if file_des:
                log.info(
                    "Checking for any residue logs that might have been "
                    "added while log rotation was being performed"
                )
                file_des.seek(offset)
                for event in file_des.readlines():
                    event_data.append(event)
    return event_data



