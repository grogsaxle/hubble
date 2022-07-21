
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

from hubblestack.exceptions import CommandExecutionError
from hubblestack import __version__
import hubblestack.log

import collections.abc

def dict_update(dest, upd, recursive_update=True, merge_lists=False):
    """
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    This behavior is only activated when recursive_update=True. By default
    merge_lists=False.
    """
    if (not isinstance(dest, collections.abc.Mapping)) or (not isinstance(upd, collections.abc.Mapping)):
        raise TypeError("Cannot update using non-dict types in dictupdate.update()")
    updkeys = list(upd.keys())
    if not set(list(dest.keys())) & set(updkeys):
        recursive_update = False
    if recursive_update:
        for key in updkeys:
            val = upd[key]
            try:
                dest_subkey = dest.get(key, None)
            except AttributeError:
                dest_subkey = None
            if isinstance(dest_subkey, collections.abc.Mapping) and isinstance(val, collections.abc.Mapping):
                ret = _dict_update(dest_subkey, val, merge_lists=merge_lists)
                dest[key] = ret
            elif isinstance(dest_subkey, list) and isinstance(val, list):
                if merge_lists:
                    dest[key] = dest.get(key, []) + val
                else:
                    dest[key] = upd[key]
            else:
                dest[key] = upd[key]
    else:
        for k in upd:
            dest[k] = upd[k]
    return dest

def get_top_data(topfile):
    """
    Function that reads the topfile and returns a list of matched configs that
    represent .yaml config files
    """
    topfile = __mods__["cp.cache_file"](topfile)

    if not topfile:
        raise CommandExecutionError("Topfile not found.")

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        raise CommandExecutionError("Could not load topfile: {0}".format(exc))

    if not isinstance(topdata, dict) or "nebula" not in topdata or not isinstance(topdata["nebula"], list):
        raise CommandExecutionError(
            "Nebula topfile not formatted correctly. "
            'Note that under the "nebula" key the data should now be'
            " formatted as a list of single-key dicts."
        )

    topdata = topdata["nebula"]

    ret = []

    for topmatch in topdata:
        for match, data in topmatch.items():
            if __mods__["match.compound"](match):
                ret.extend(data)

    return ret
