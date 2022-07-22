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


import copy
import fnmatch
import json
import logging
import os
import re
import time
import hashlib
import yaml
from inspect import getfullargspec

import hubblestack.utils.files
import hubblestack.utils.platform

from hubblestack.modules.nebula.helper import dict_update, get_top_data

from hubblestack.exceptions import CommandExecutionError
from hubblestack import __version__
import hubblestack.log


log = logging.getLogger(__name__)

CRC_BYTES = 256

__virtualname__ = "nebula"
__RESULT_LOG_OFFSET__ = {}
OSQUERYD_NEEDS_RESTART = False
IS_FIPS_ENABLED = True if "usedforsecurity" in getfullargspec(hashlib.new).kwonlyargs else False


def __virtual__():
    return __virtualname__


def queries(
    query_group,
    query_file=None,
    verbose=False,
    report_version_with_day=True,
    topfile_for_mask=None,
    mask_passwords=False,
):
    """
    Run the set of queries represented by ``query_group`` from the
    configuration in the file query_file

    query_group
        Group of queries to run

    query_file
        salt:// file which will be parsed for osquery queries

    verbose
        Defaults to False. If set to True, more information (such as the query
        which was run) will be included in the result.

    topfile_for_mask
        This is the location of the top file from which the masking information
        will be extracted.

    mask_passwords
        Defaults to False. If set to True, passwords mentioned in the
        return object are masked.

    CLI Examples:

    .. code-block:: bash

        salt '*' nebula.queries day
        salt '*' nebula.queries hour verbose=True
        salt '*' nebula.queries hour pillar_key=sec_osqueries
    """
    # sanity check of query_file: if not present, add it
    if hubblestack.utils.platform.is_windows():
        query_file = query_file or "salt://hubblestack_nebula_v2/hubblestack_nebula_win_queries.yaml"
    else:
        query_file = query_file or "salt://hubblestack_nebula_v2/hubblestack_nebula_queries.yaml"
    if not isinstance(query_file, list):
        query_file = [query_file]

    # 'POP' is for tracking persistent opts protection
    if os.environ.get("NOISY_POP_DEBUG"):
        log.error("POP adding nebula_queries to __opts__ (id=%d)", id(__opts__))

    query_data = _get_query_data(query_file)
    __opts__["nebula_queries"] = query_data

    if query_data is None or not query_group:
        return None

    if "osquerybinpath" not in __grains__:
        if query_group == "day":
            log.warning("osquery not installed on this host. Returning baseline data")
            return _build_baseline_osquery_data(report_version_with_day)
        log.debug("osquery not installed on this host. Skipping.")
        return None

    query_data = query_data.get(query_group, {})

    schedule_time = time.time()

    # run the osqueryi queries
    success, timing, ret = _run_osquery_queries(query_data, verbose)

    if success is False and hubblestack.utils.platform.is_windows():
        log.error("osquery does not run on windows versions earlier than Server 2008 and Windows 7")
        if query_group == "day":
            ret = [
                {
                    "fallback_osfinger": {
                        "data": [
                            {
                                "osfinger": __grains__.get("osfinger", __grains__.get("osfullname")),
                                "osrelease": __grains__.get("osrelease", __grains__.get("lsb_distrib_release")),
                            }
                        ],
                        "result": True,
                    }
                },
                {
                    "fallback_error": {
                        "data": "osqueryi is installed but not compatible with this version of windows",
                        "result": True,
                    }
                },
            ]
            return ret
        return None

    if __mods__["config.get"]("splunklogging", False):
        log.debug("Logging osquery timing data to splunk")
        timing_data = {"query_run_length": timing, "schedule_time": schedule_time}
        hubblestack.log.emit_to_splunk(timing_data, "INFO", "hubblestack.osquery_timing")

    if query_group == "day" and report_version_with_day:
        ret.append(hubble_versions())

    ret = _update_osquery_results(ret)

    if mask_passwords:
        _mask_object(ret, topfile_for_mask)

    return ret


def _build_baseline_osquery_data(report_version_with_day):
    """
    Build the baseline data to be returned if osquery is not installed on the host.
    """
    # Match the formatting of normal osquery results. Not super readable,
    # but just add new dictionaries to the list as we need more data
    ret = [
        {
            "fallback_osfinger": {
                "data": [
                    {
                        "osfinger": __grains__.get("osfinger", __grains__.get("osfullname")),
                        "osrelease": __grains__.get("osrelease", __grains__.get("lsb_distrib_release")),
                    }
                ],
                "result": True,
            }
        }
    ]
    if "pkg.list_pkgs" in __mods__:
        ret.append(
            {
                "fallback_pkgs": {
                    "data": [{"name": k, "version": v} for k, v in __mods__["pkg.list_pkgs"]().items()],
                    "result": True,
                }
            }
        )
    uptime = __mods__["status.uptime"]()
    if isinstance(uptime, dict):
        uptime = uptime.get("seconds", __mods__["cmd.run"]("uptime"))
    ret.append({"fallback_uptime": {"data": [{"uptime": uptime}], "result": True}})
    if report_version_with_day:
        ret.append(hubble_versions())

    return ret


def _run_osqueryi_query(query, query_sql, timing, verbose):
    """
    Run the osqueryi query in query_sql and return the result
    """
    max_file_size = 104857600
    augeas_lenses = "/opt/osquery/lenses"
    query_ret = {"result": True}

    # Run the osqueryi query
    cmd = [
        __grains__["osquerybinpath"],
        "--read_max",
        max_file_size,
        "--json",
        "--augeas_lenses",
        augeas_lenses,
        query_sql,
    ]

    if hubblestack.utils.platform.is_windows():
        # augeas_lenses are not available on windows
        cmd = [__grains__["osquerybinpath"], "--read_max", max_file_size, "--json", query_sql]

    time_start = time.time()
    res = __mods__["cmd.run_all"](cmd, timeout=600)
    time_end = time.time()
    timing[query["query_name"]] = time_end - time_start
    if res["retcode"] == 0:
        query_ret["data"] = json.loads(res["stdout"])
    else:
        if "Timed out" in res["stdout"]:
            # this is really the best way to tell without getting fancy
            log.error("TIMEOUT during osqueryi execution name=%s", query["query_name"])
        query_ret["result"] = False
        query_ret["error"] = res["stderr"]
    if verbose:
        tmp = copy.deepcopy(query)
        tmp["query_result"] = query_ret
    else:
        tmp = {query["query_name"]: query_ret}

    return tmp


def _run_osquery_queries(query_data, verbose):
    """
    Go over the query data in the osquery query file, run each query
    and return the aggregated results.
    """
    ret = []
    timing = {}
    success = True
    for name, query in query_data.items():
        query["query_name"] = name
        query_sql = query.get("query")
        if not query_sql:
            continue
        if "attach" in query_sql.lower() or "curl" in query_sql.lower():
            log.critical(
                "Skipping potentially malicious osquery query '%s' " "which contains either 'attach' or 'curl': %s",
                name,
                query_sql,
            )
            continue

        # Run osquery query
        query_ret = _run_osqueryi_query(query, query_sql, timing, verbose)
        try:
            if query_ret["query_result"]["result"] is False or query_ret[name]["result"] is False:
                success = False
        except KeyError:
            pass
        ret.append(query_ret)

    return success, timing, ret


def _update_osquery_results(ret):
    """
    Go over the data in the results obtained by running osquery queries and update by JSONIFYing
    Returns the updated version.
    """
    for data in ret:
        for _query_name, query_ret in data.items():
            if "data" not in query_ret:
                continue
            for result in query_ret["data"]:
                for key, value in result.items():
                    if value and isinstance(value, str) and value.startswith("__JSONIFY__"):
                        result[key] = json.loads(value[len("__JSONIFY__") :])

    return ret


def _get_query_data(query_file):
    """
    Helper function that extracts the query data from the query file and returns it.
    """
    query_data = {}
    for file_path in query_file:
        if "salt://" in file_path:
            orig_fh = file_path
            file_path = __mods__["cp.cache_file"](file_path)
        if not file_path:
            log.error("Could not find file %s.", orig_fh)
            return None
        if os.path.isfile(file_path):
            with open(file_path, "r") as yaml_file:
                f_data = yaml.safe_load(yaml_file)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError("File data is not formed as a dict {0}".format(f_data))
                query_data = dict_update(query_data, f_data, recursive_update=True, merge_lists=True)
    return query_data


def fields(*args):
    """
    Use config.get to retrieve custom data based on the keys in the `*args`
    list.

    Arguments:

    *args
        List of keys to retrieve
    """
    ret = {}
    for field in args:
        ret["custom_{0}".format(field)] = __mods__["config.get"](field)
    # Return it as nebula data
    if ret:
        return [{"custom_fields": {"data": [ret], "result": True}}]
    return []


def version():
    """
    Report version of this module
    """
    return __version__


def hubble_versions():
    """
    Report version of all hubble modules as query
    """
    versions = {"nova": __version__, "nebula": __version__, "pulsar": __version__, "quasar": __version__}

    return {"hubble_versions": {"data": [versions], "result": True}}


def top(query_group, topfile="salt://hubblestack_nebula_v2/top.nebula", topfile_for_mask=None, mask_passwords=False):
    """
    Run the queries represented by query_group from the configuration files extracted from topfile
    """
    if hubblestack.utils.platform.is_windows():
        topfile = "salt://hubblestack_nebula_v2/win_top.nebula"

    configs = get_top_data(topfile, __mods__)

    configs = ["salt://hubblestack_nebula_v2/" + config.replace(".", "/") + ".yaml" for config in configs]

    return queries(
        query_group,
        query_file=configs,
        verbose=False,
        report_version_with_day=True,
        topfile_for_mask=topfile_for_mask,
        mask_passwords=mask_passwords,
    )




def _mask_object(object_to_be_masked, topfile):
    """
    Given an object with potential secrets (or other data that should not be
    returned), mask the contents of that object as configured in the mask
    configuration file. The mask configuration file used is defined by the
    top data in the ``topfile`` argument.

    If multiple mask.yaml files are matched in the topfile, the data within
    them will be recursively merged.

    If no matching mask_files are found in the top.mask file, no masking will
    happen.

    Note that this function has side effects: alterations to
    ``object_to_be_masked`` will be made in place.

    Sample mask.yaml data (with inline documentation):

    .. code-block:: yaml

        # Pattern that will replace whatever is masked
        mask_with: '***masked*by*hubble***'

        # Target and mask strings based on regex patterns
        # Can limit search specific queries and columns

        # Some osquery results are formed as lists of dicts. We can mask
        # based on variable names within these dicts.
        blacklisted_objects:

            - query_names:
              - 'running_procs'
              - 'listening_procs'          # List of name(s) of the osquery to be masked.
                                           # Put '*' to match all queries. Note
                                           # that query_names doesn't support
                                           # full globbing. '*' is just given
                                           # special treatment.
              column: 'environment'  # Column name in the osquery to be masked.
                                       No regex or glob support
              custom_mask_column: 'environment'  # Column name which stores environment variables
              custom_mask_key: '__hubble_mask__' # Env variable to look for constructing custom
                                                   blacklist of patterns
              attribute_to_check: 'variable_name' # Optional attribute
                                                  # In the inner dict, this is the key
                                                  # to check for blacklisted_patterns
                                                  # Will skipped if column specified is of
                                                    type 'String'
              attributes_to_mask: # Optional attribute, Values under these keys in the dict will be
                - 'value'  # masked, assuming one of the blacklisted_patterns
                           # is found under attribute_to_check in the same dict
                           # Will be skipped if column specified is of type 'String'
              blacklisted_patterns:  # Strings to look for under attribute_to_check.
                                       Conditional Globbing support.
                - 'ETCDCTL_READ_PASSWORD'
                - 'ETCDCTL_WRITE_PASSWORD'
                - '*PASSWORD*'  # Enable globbing by setting 'enable_globbing_in_nebula_masking'
                                  to True, default False

    blacklisted_patterns (for blacklisted_objects)

        For objects, the pattern applies to the variable name, and doesn't
        support regex. For example, you might have data formed like this::

            [{ value: 'SOME_PASSWORD', variable_name: 'ETCDCTL_READ_PASSWORD' }]

        The attribute_to_check would be ``variable_name`` and the pattern would
        be ``ETCDCTL_READ_PASSWORD``. The attribute_to_mask would be ``value``.
        All dicts with ``variable_name`` in the list of blacklisted_patterns
        would have the value under their ``value`` key masked.
    """
    try:
        mask = {}
        if topfile is None:
            # We will maintain backward compatibility by keeping two versions of
            # top files and mask files for now
            # Once all hubble servers are updated, we can remove old version of
            # top file and mask file
            # Similar to what we have for nebula and nebula_v2 for older versions and
            # newer versions of profiles
            topfile = "salt://hubblestack_nebula_v2/top_v2.mask"
        mask_files = get_top_data(topfile, __mods__)
        mask_files = [
            "salt://hubblestack_nebula_v2/" + mask_file.replace(".", "/") + ".yaml" for mask_file in mask_files
        ]
        if not mask_files:
            mask_files = []
        for mask_file in mask_files:
            if "salt://" in mask_file:
                orig_fh = mask_file
                mask_file = __mods__["cp.cache_file"](mask_file)
            if not mask_file:
                log.error("Could not find file %s.", orig_fh)
                return None
            if os.path.isfile(mask_file):
                with open(mask_file, "r") as yfile:
                    f_data = yaml.safe_load(yfile)
                    if not isinstance(f_data, dict):
                        raise CommandExecutionError("File data is not formed as a dict {0}".format(f_data))
                    mask = dict_update(mask, f_data, recursive_update=True, merge_lists=True)

        log.debug("Masking data: %s", mask)

        # Backwards compatibility with mask_by
        mask_with = mask.get("mask_with", mask.get("mask_by", "REDACTED"))

        log.info("Total number of results to check for masking: %d", len(object_to_be_masked))
        globbing_enabled = __opts__.get("enable_globbing_in_nebula_masking")

        for blacklisted_object in mask.get("blacklisted_objects", []):
            query_names = blacklisted_object["query_names"]
            column = blacklisted_object["column"]  # Can be converted to list as well in future
            perform_masking_kwargs = {
                "blacklisted_object": blacklisted_object,
                "mask_with": mask_with,
                "globbing_enabled": globbing_enabled,
            }
            if "*" in query_names:
                # This means wildcard is specified and each event should be masked, if applicable
                _mask_object_helper(object_to_be_masked, perform_masking_kwargs, column)
            else:
                # Perform masking on results of specific queries specified in 'query_names'
                for query_name in query_names:
                    _mask_object_helper(object_to_be_masked, perform_masking_kwargs, column, query_name)

    except Exception:
        log.exception("An error occured while masking the passwords.", exc_info=True)

    # Object masked in place, so we don't need to return the object
    return True


def _mask_object_helper(object_to_be_masked, perform_masking_kwargs, column, query_name=None):
    """
    Helper function used to mask an object
    """
    for obj in object_to_be_masked:
        if "action" in obj:
            # This means data is generated by osquery daemon
            _mask_event_data(
                obj,
                query_name,
                column,
                perform_masking_kwargs["blacklisted_object"],
                perform_masking_kwargs["mask_with"],
                perform_masking_kwargs["globbing_enabled"],
            )
        else:
            # This means data is generated by osquery interactive shell
            kwargs = {
                "query_name": query_name,
                "column": column,
                "perform_masking_kwargs": perform_masking_kwargs,
                "custom_args": {"should_break": True},
            }
            if query_name:
                # No log_error here, since we didn't reference a specific query
                kwargs["custom_args"]["log_error"] = True
                data = obj.get(query_name, {"data": []})["data"]
                _mask_interactive_shell_data(data, kwargs)
            else:
                kwargs["custom_args"]["log_error"] = False
                for query_name, query_ret in obj.items():
                    data = query_ret["data"]
                    _mask_interactive_shell_data(data, kwargs)


def _mask_interactive_shell_data(data, kwargs):
    """
    Function that masks the data generated by an interactive osquery shell
    """
    for query_result in data:
        status, _blacklisted_object, query_result = _mask_event_data_helper(event_data=query_result, **kwargs)
        if kwargs["custom_args"]["log_error"]:
            # if the column in not present in one data-object, it will
            # not be present in others as well. Break in that case.
            # This will happen only if mask.yaml is malformed
            if not status:
                break


def _mask_event_data(object_to_be_masked, query_name, column, blacklisted_object, mask_with, globbing_enabled):
    """
    This method is responsible for masking potential secrets in event data generated by
    osquery daemon. This will handle logs format of both differential and snapshot types

    Logs generated by 'osqueryi' would not reach here due checks in parent method

    object_to_be_masked
        data structure to mask recursively

    query_name
        Perform masking only if query name in 'object_to_be_masked' matches the 'query_name'

    column
        column in which masking is to be performed

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    """
    if not query_name:
        query_name = object_to_be_masked["name"]
    perform_masking_kwargs = {
        "blacklisted_object": blacklisted_object,
        "mask_with": mask_with,
        "globbing_enabled": globbing_enabled,
    }

    if object_to_be_masked["action"] == "snapshot" and query_name == object_to_be_masked["name"]:
        # This means we have event data of type 'snapshot'
        for snap_object in object_to_be_masked["snapshot"]:
            status, blacklisted_object, snap_object = _mask_event_data_helper(
                event_data=snap_object,
                query_name=query_name,
                column=column,
                perform_masking_kwargs=perform_masking_kwargs,
                custom_args={"should_break": True, "log_error": True},
            )
            if not status:
                break
    elif query_name == object_to_be_masked["name"]:
        _status, _blacklisted_object, _q_result = _mask_event_data_helper(
            event_data=object_to_be_masked["columns"],
            query_name=query_name,
            column=column,
            perform_masking_kwargs=perform_masking_kwargs,
            custom_args={"should_break": False, "log_error": True},
        )
    else:
        # Unable to match query_name
        log.debug("Skipping masking, as event data is not for query: %s", query_name)


def _custom_blacklisted_object(blacklisted_object, mask_column):
    """
    Construct custom blacklisted patterns based on custom_mask_key value of blacklisted_object
    """
    for column_field in mask_column:
        try:
            if (
                "variable_name" in column_field
                and "value" in column_field
                and column_field["variable_name"] == blacklisted_object["custom_mask_key"]
            ):
                log.debug(
                    "Constructing custom blacklisted patterns based on \
                          environment variable '%s'",
                    blacklisted_object["custom_mask_key"],
                )
                blacklisted_object["custom_blacklist"] = [
                    field.strip()
                    for field in column_field["value"].replace(" ", ",").split(",")
                    if field.strip() and field.strip() != blacklisted_object["custom_mask_key"]
                ]
            else:
                log.debug(
                    "Custom mask variable not set in environment. Custom mask key used: %s",
                    blacklisted_object["custom_mask_key"],
                )
        except Exception as exc:
            log.error("Failed to generate custom blacklisted patterns based on hubble mask key")
            log.error("Got error: %s", exc)

    return blacklisted_object


def _mask_event_data_helper(event_data, query_name, column, perform_masking_kwargs, custom_args):
    """
    Helper function for _mask_event_data that masks secrets in event data
    generated by osquery daemon taking into account the type - differential or snashot.

    perform_masking_kwargs
        Dictionary that acts as **kwargs for the _perform_masking function, holding
        blacklisted_object, mask_with and globbing_enabled

    custom_args
        A dictionary containing:
            'should_break' key with a True value if it should return when the column is not
             found in event_data and False if it should not return on that branch
            'log_error' key with a True value if it should log an error when the column is not
            found in event_data and False if that is not considered an error
    """
    blacklisted_object = perform_masking_kwargs["blacklisted_object"]
    # Name of column that stores environment variables
    custom_mask_column = blacklisted_object.get("custom_mask_column", "")
    enable_local_masking = blacklisted_object.get("enable_local_masking", False)
    if enable_local_masking is True and custom_mask_column and custom_mask_column in event_data:
        log.debug("Checking if custom mask patterns are set in environment")
        mask_column = event_data[custom_mask_column]
        if mask_column and isinstance(mask_column, list):
            blacklisted_object = _custom_blacklisted_object(blacklisted_object, mask_column)
    if column not in event_data or (isinstance(event_data[column], str) and event_data[column].strip() != ""):
        if custom_args["log_error"]:
            log.error("masking data references a missing column %s in query %s", column, query_name)
        if custom_args["should_break"]:
            return False, blacklisted_object, event_data
    if event_data[column] != "" and isinstance(event_data[column], str):
        # If column is of 'string' type, then replace pattern in-place
        # No need for recursion here
        value = event_data[column]
        for pattern in blacklisted_object["blacklisted_patterns"]:
            value = re.sub(pattern + "()", r"\1" + perform_masking_kwargs["mask_with"] + r"\3", value)
        event_data[column] = value
    else:
        _perform_masking(event_data[column], **perform_masking_kwargs)
        blacklisted_object.pop("custom_blacklist", None)
    return True, blacklisted_object, event_data


def _perform_masking(object_to_mask, blacklisted_object, mask_with, globbing_enabled):
    """
    This function is used as a wrapper to _recursively_mask_objects function.
    It's main usage is to set 'blacklisted_patterns'.
    If custom blacklisted patterns are present they will used.

    Fallback to blacklisted_patterns specified in mask file if no custom hubble mask is provided.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    blacklisted_patterns
        List of blacklisted patterns which will be used to identify if a field is to be masked

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    """
    enable_local_masking = blacklisted_object.get("enable_local_masking", False)
    enable_global_masking = blacklisted_object.get("enable_global_masking", False)
    blacklisted_patterns = None

    if enable_local_masking is True and enable_global_masking is True:
        # For now, we will be performing masking based on global list as well as dynamic list
        # present in process's environment variable
        # If there's no noticeable performance impact then we will continue using both else
        # switch to using either global blacklist or dynamic blacklist as specified by
        # blacklisted_object['custom_mask_key'] in process's environment
        if "custom_blacklist" in blacklisted_object and blacklisted_object["custom_blacklist"]:
            if blacklisted_object.get("blacklisted_patterns", None):
                blacklisted_patterns = (
                    blacklisted_object["blacklisted_patterns"] + blacklisted_object["custom_blacklist"]
                )
                blacklisted_patterns = list(set(blacklisted_patterns))  # remove duplicates, if any
                log.debug("Appending custom blacklisted patterns in global blacklist for masking")
            else:
                blacklisted_patterns = blacklisted_object["custom_blacklist"]
                log.debug("Local blacklist missing, using global blacklist for masking")
        else:
            if blacklisted_object.get("blacklisted_patterns", None):
                blacklisted_patterns = blacklisted_object["blacklisted_patterns"]
                log.debug("No local blacklist found, using global blacklist only for masking")
    elif enable_global_masking is True:
        if blacklisted_object.get("blacklisted_patterns", None):
            blacklisted_patterns = blacklisted_object["blacklisted_patterns"]
            log.debug("Only global masking is enabled.")
    elif enable_local_masking is True:
        if "custom_blacklist" in blacklisted_object and blacklisted_object["custom_blacklist"]:
            blacklisted_patterns = blacklisted_object["custom_blacklist"]
            log.debug("Only local masking is enabled.")
    else:
        log.debug("Both global and local masking is disabled, skipping masking of results.")

    if blacklisted_patterns:
        _recursively_mask_objects(
            object_to_mask, blacklisted_object, blacklisted_patterns, mask_with, globbing_enabled
        )


def _recursively_mask_objects(object_to_mask, blacklisted_object, blacklisted_patterns, mask_with, globbing_enabled):
    """
    This function is used by ``_mask_object()`` to mask passwords contained in
    an osquery data structure (formed as a list of dicts, usually). Since the
    lists can sometimes be nested, recurse through the lists.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    blacklisted_patterns
        List of blacklisted patterns which will be used to identify if a field is to be masked

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    """
    if isinstance(object_to_mask, list):
        for child in object_to_mask:
            log.debug("Recursing object %s", child)
            _recursively_mask_objects(child, blacklisted_object, blacklisted_patterns, mask_with, globbing_enabled)
    elif globbing_enabled and blacklisted_object["attribute_to_check"] in object_to_mask:
        mask = False
        for blacklisted_pattern in blacklisted_patterns:
            if fnmatch.fnmatch(object_to_mask[blacklisted_object["attribute_to_check"]], blacklisted_pattern):
                mask = True
                log.info("Attribute %s will be masked.", object_to_mask[blacklisted_object["attribute_to_check"]])
                break
        if mask:
            for key in blacklisted_object["attributes_to_mask"]:
                if key in object_to_mask:
                    object_to_mask[key] = mask_with
    elif (
        (not globbing_enabled)
        and blacklisted_object["attribute_to_check"] in object_to_mask
        and object_to_mask[blacklisted_object["attribute_to_check"]] in blacklisted_patterns
    ):
        for key in blacklisted_object["attributes_to_mask"]:
            if key in object_to_mask:
                object_to_mask[key] = mask_with



def query(query):
    """
    Run the osquery `query` and return the results.

    query
        String containgin `SQL` query to be run by osquery

    """
    max_file_size = 104857600
    if "attach" in query.lower() or "curl" in query.lower():
        log.critical(
            "Skipping potentially malicious osquery query which contains either" " 'attach' or 'curl': %s", query
        )
        return None
    query_ret = {"result": True}

    # Run the osqueryi query
    cmd = [__grains__["osquerybinpath"], "--read_max", max_file_size, "--json", query]
    res = __mods__["cmd.run_all"](cmd, timeout=600)
    if res["retcode"] == 0:
        query_ret["data"] = json.loads(res["stdout"])
    else:
        if "Timed out" in res["stdout"]:
            # this is really the best way to tell without getting fancy
            log.error("TIMEOUT during osqueryi execution %s", query)
        query_ret["result"] = False
        query_ret["error"] = res["stderr"]

    return query_ret

