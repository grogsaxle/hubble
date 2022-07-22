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


import logging
import os
import shutil
import yaml
from inspect import getfullargspec

import hubblestack.utils.files
import hubblestack.utils.platform
from hubblestack.modules.nebula.helper import dict_update, get_top_data

from hubblestack.exceptions import CommandExecutionError
from hubblestack import __version__
import hubblestack.log

from hubblestack.status import HubbleStatus

log = logging.getLogger(__name__)


def extensions(extensions_topfile=None, extensions_loadfile=None):
    """
    Given a topfile location, parse the topfile and lay down osquery extensions
    and other files as shown in the targeted profiles.

    The default topfile location is
    ``salt://hubblestack_nebula_v2/top.extensions``

    You can also specify a custom extensions loadfile for osquery, otherwise
    the configured path in ``osquery_extensions_loadfile`` will be used.

    If extensions_loadfile is defined, osqueryd will be restarted, if it is
    found to be running.

    Add ``remove: True`` to a file entry to delete the file. This allows for
    removing a no-longer-needed extension.

    By default, files can only be written under ``/opt/osquery/extensions`` to
    prevent accidental or malicious overwriting of system files. To change this
    whitelist, you can add ``osquery_extensions_path_whitelist`` in your
    hubble config. Form the configuration as a list of acceptable prefixes for
    files delivered by this module. Include trailing slashes, as we just use
    a "startswith" comparison::

        osquery_extensions_path_whitelist:
            - /opt/osquery/extensions/
            - /opt/osquery/augeas/

    Profile example::

        files:
            - path: salt://hubblestack_nebula_v2/extensions/test.ext
              dest: /opt/osquery/extensions/test.ext
              extension_autoload: True   # optional, defaults to False
              mode: '600'                # optional, default shown
              user: root                 # optional, default shown
              group: root                # optional, default shown
            - path: salt://hubblestack_nebula_v2/extensions/conf/test.json
              dest: /opt/osquery/extensions/conf/test.json
              extension_autoload: False  # optional, defaults to False
              mode: '600'                # optional, default shown
              user: root                 # optional, default shown
              group: root                # optional, default shown
    """
    if hubblestack.utils.platform.is_windows():
        log.error("Windows is not supported for nebula.extensions")
        return False

    if extensions_topfile is None:
        extensions_topfile = "salt://hubblestack_nebula_v2/top.extensions"

    try:
        topdata = get_top_data(extensions_topfile, __mods__)
    except Exception:
        log.info("An error occurred fetching top data for nebula.extensions.", exc_into=True)
        return False

    if not topdata:
        return True

    topdata = ["salt://hubblestack_nebula_v2/" + config.replace(".", "/") + ".yaml" for config in topdata]

    files = _get_file_data(topdata)
    if files and isinstance(files, list):
        if extensions_loadfile is None:
            extensions_loadfile = __opts__.get("osquery_extensions_loadfile")

        autoload = _parse_file_data(files)

        if extensions_loadfile:
            try:
                with open(extensions_loadfile, "w") as ext_file:
                    for extension in autoload:
                        ext_file.write(extension)
                        ext_file.write("\n")
            except Exception:
                log.error("Something went wrong writing osquery extensions.load.", exc_info=True)

            # Leave flag to restart osqueryd
            global OSQUERYD_NEEDS_RESTART
            OSQUERYD_NEEDS_RESTART = True
    return True


def _get_file_data(topdata):
    """
    Helper function that extracts the files from topdata and returns them as a list
    """
    extension_data = {}

    for ext_file in topdata:
        if "salt://" in ext_file:
            orig_fh = ext_file
            ext_file = __mods__["cp.cache_file"](ext_file)
        if not ext_file:
            log.error("Could not find file %s.", orig_fh)
            continue
        if os.path.isfile(ext_file):
            with open(ext_file, "r") as file_data:
                f_data = yaml.safe_load(file_data)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError("File data is not formed as a dict {0}".format(f_data))
                extension_data = dict_update(extension_data, f_data, recursive_update=True, merge_lists=True)

    return extension_data.get("files")


def _parse_file_data(files):
    """
    Helper function that goes over each file in files, checks if whitelisted
    and if it should be removed.
    Returns a list of valid files that have 'extension_autoload' set to True
    """
    autoload = []
    for file_data in files:
        path = file_data.get("path")
        dest = file_data.get("dest")
        dest = os.path.abspath(dest)

        dest_ok = False
        whitelisted_paths = __opts__.get("osquery_extensions_path_whitelist", ["/opt/osquery/extensions/"])
        if not isinstance(whitelisted_paths, list):
            whitelisted_paths = list(whitelisted_paths)
        for whitelisted_path in whitelisted_paths:
            if dest.startswith(whitelisted_path):
                dest_ok = True
        if not dest_ok:
            log.error("Skipping file outside of osquery_extensions_path_whitelist: %s", dest)
            continue

        # Allow for file removals
        if file_data.get("remove"):
            if dest and os.path.exists(dest):
                try:
                    os.unlink(dest)
                except Exception:
                    pass
            continue

        if not path or not dest:
            log.error("path or dest missing in files entry: %s", file_data)
            continue

        result = _get_file(**file_data)

        if result and file_data.get("extension_autoload", False):
            autoload.append(dest)

    return autoload


def _get_file(path, dest, mode="600", user="root", group="root"):
    """
    Cache a file from a salt ``path`` to a local ``dest`` with the given
    attributes.
    """
    try:
        mode = str(mode)
        local_path = __mods__["cp.cache_file"](path)
        if not local_path:
            log.error(
                "Couldn't cache %s to %s. This is probably due to " "an issue finding the file in S3.", path, dest
            )
            return False
        shutil.copyfile(local_path, dest)
        ret = __mods__["file.check_perms"](name=local_path, ret=None, user=user, group=group, mode=mode)

        return ret[0]["result"]
    except Exception:
        log.error("An error occurred getting file %s", path, exc_info=True)
        return False
