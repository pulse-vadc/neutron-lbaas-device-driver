#!/usr/bin/env python
#
# Copyright 2017 Brocade Communications Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Matthew Geldert (mgeldert@pulsesecure.net), Pulse Secure, LLC
#

from driver_common import vTMDeviceDriverCommon, logging_wrapper
from neutron_lbaas.common.exceptions import LbaasException
from openstack_connector import OpenStackInterface
from oslo_config import cfg
from oslo_log import log as logging
from vtm import vTM
from time import sleep
from traceback import format_exc

LOG = logging.getLogger(__name__)


class BrocadeDeviceDriverV2(vTMDeviceDriverCommon):
    """
    Shared vTM Cluster Version
    """

    def __init__(self, plugin):
        # Build a list of all vTMs in the cluster
        self.vtms = [
            vTM(
                "https://{}:{}/api/tm/{}".format(
                    server,
                    cfg.CONF.vtm_settings.rest_port,
                    cfg.CONF.vtm_settings.api_version
                ),
                cfg.CONF.vtm_settings.username,
                cfg.CONF.vtm_settings.password
            )
            for server in cfg.CONF.lbaas_settings.admin_servers
        ]
        super(BrocadeDeviceDriverV2, self).__init__()
        LOG.info(_(
            "\nShared Brocade vTM LBaaS module initialized with {} cluster "
            "members.\nPlease restart the Neutron server if you manually "
            "add/remove any vTMs from the cluster.".format(len(self.vtms))
        ))

#################
# LOADBALANCERS #
#################

    @logging_wrapper
    def create_loadbalancer(self, lb):
        self.update_loadbalancer(lb, None)

    @logging_wrapper
    def update_loadbalancer(self, lb, old):
        vtm = self._get_vtm()
        # Create a Traffic IP group for the loadbalancer's VIP address
        tip_group_nodes = self._get_tip_group_nodes(vtm)
        tip_config = {"properties": {
            "basic": {
                "enabled": lb.admin_state_up,
                "ipaddresses": [lb.vip_address],
                "machines": tip_group_nodes['machines'],
                "slaves": tip_group_nodes['passive'],
                "note": "{} ({})".format(lb.name, lb.tenant_id)
            }
        }}
        vtm.tip_group.create(lb.id, config=tip_config)
        # If applicable, add IP to each vTM's "allowed-address-pairs"
        if not old:
            self.openstack_connector.add_ip_to_ports(
                lb.vip_address, cfg.CONF.lbaas_settings.ports
            )
        # If applicable, update each vTM's "allowed-address-pairs"
        elif old.vip_address != lb.vip_address:
            self.openstack_connector.add_ip_to_ports(
                lb.vip_address, cfg.CONF.lbaas_settings.ports
            )
            self.openstack_connector.delete_ip_from_ports(
                old.vip_address, cfg.CONF.lbaas_settings.ports
            )

    @logging_wrapper
    def delete_loadbalancer(self, lb):
        vtm = self._get_vtm()
        # Delete the Traffic IP group for the loadbalancer's VIP address
        vtm.tip_group.delete(lb.id)
        # Delete IP from each vTM's "allowed-address-pairs"
        self.openstack_connector.delete_ip_from_ports(
            lb.vip_address, cfg.CONF.lbaas_settings.ports
        )

#############
# LISTENERS #
#############

    @logging_wrapper
    def update_listener(self, listener, old):
        vtm = self._get_vtm()
        listen_on_settings = {}
        listen_on_settings['listen_on_traffic_ips'] = [
            listener.loadbalancer.id
        ]
        listen_on_settings['listen_on_any'] = False
        super(BrocadeDeviceDriverV2, self).update_listener(
            listener, old, vtm, listen_on_settings, False,
            "{} ({})".format(listener.name, listener.tenant_id)
        )

    @logging_wrapper
    def delete_listener(self, listener):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).delete_listener(listener,vtm,False)

#########
# POOLS #
#########

    @logging_wrapper
    def update_pool(self, pool, old):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).update_pool(
            pool, old, vtm, "{} ({})".format(pool.name, pool.tenant_id)
        )

    @logging_wrapper
    def delete_pool(self, pool):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).delete_pool(pool, vtm)

############
# MONITORS #
############

    @logging_wrapper
    def update_healthmonitor(self, monitor, old):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).update_healthmonitor(
            monitor, old, vtm,
            "{} ({})".format(monitor.pool.name, monitor.tenant_id)
        )

    @logging_wrapper
    def delete_healthmonitor(self, monitor):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).delete_healthmonitor(monitor, vtm)

###############
# L7 POLICIES #
###############

    @logging_wrapper
    def update_l7_policy(self, policy, old):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).update_l7_policy(policy, old, vtm)

    @logging_wrapper
    def delete_l7_policy(self, policy):
        vtm = self._get_vtm()
        super(BrocadeDeviceDriverV2, self).delete_l7_policy(policy, vtm)

#########
# STATS #
#########

    @logging_wrapper
    def stats(self, loadbalancer):
        vtm = self._get_vtm()
        return super(BrocadeDeviceDriverV2, self).stats(
            vtm, loadbalancer.vip_address
        )

########
# MISC #
########

    def _get_tip_group_nodes(self, vtm):
        # Get a tally of how many TIP groups the machine is currently in...
        cluster_members = vtm.get_nodes_in_cluster()
        tip_count = {
            member: {"active": 0, "total": 0} for member in cluster_members
        }
        for tip_id in vtm.tip_groups.list():
            tip_group = vtm.tip_group.get(tip_id)
            for member in tip_group.machines:
                if member not in tip_group.slaves:
                    tip_count[member]['active'] += 1
                tip_count[member]['total'] += 1
        # Work out which machines are best to be used for the new TIP group:
        # Choose active member...
        active = sorted(
            cluster_members,
            key=lambda m: (tip_count[m]['active'], tip_count[m]['total'])
        )[0]
        # Choose passive members...
        passive_member_count = min(
            cfg.CONF.lbaas_settings.passive_vtms,
            len(cluster_members) - 1
        )
        if passive_member_count == 0:
            passive = []
        else:
            cluster_members.remove(active)
            passive = sorted(
                cluster_members,
                key=lambda m: (tip_count[m]['total'], tip_count[m]['active'])
            )[0:passive_member_count]
        return {
            "machines": [active] + passive,
            "passive": passive
        }

    def _get_vtm(self):
        for _ in xrange(3):
            for vtm in self.vtms:
                try:
                    if not vtm.test_connectivity():
                        raise Exception("")
                    return vtm
                except:
                    pass
            sleep(3)
        raise Exception("Could not contact any vTMs in cluster")
