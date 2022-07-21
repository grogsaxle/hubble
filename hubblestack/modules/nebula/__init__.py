
from hubblestack.modules.nebula import extensions
from hubblestack.modules.nebula.extensions import extensions

from hubblestack.modules.nebula import osqueryd
from hubblestack.modules.nebula.osqueryd import check_disk_usage, osqueryd_log_parser, osqueryd_monitor
# export check_disk_usage as hubblestack.nebula.check_disk_usage

from hubblestack.modules.nebula import osquery
from hubblestack.modules.nebula.osquery import hubble_versions, __virtual__


from hubblestack.status import HubbleStatus
hubble_status = HubbleStatus(__name__, "top", "queries", "osqueryd_monitor", "osqueryd_log_parser")

@hubble_status.watch
def queries(
    query_group,
    query_file=None,
    verbose=False,
    report_version_with_day=True,
    topfile_for_mask=None,
    mask_passwords=False,
):
    return osquery.queries(query_group, query_file, verbose, report_version_with_day, topfile_for_mask, mask_passwords)

@hubble_status.watch
def top(query_group, topfile="salt://hubblestack_nebula_v2/top.nebula", topfile_for_mask=None, mask_passwords=False):
    return osquery.top(query_group, topfile, topfile_for_mask, mask_passwords)

