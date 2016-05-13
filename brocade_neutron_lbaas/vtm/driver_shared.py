#!/usr/bin/env python
#
# Copyright 2014 Brocade Communications Systems, Inc.  All rights reserved.
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
# Matthew Geldert (mgeldert@brocade.com), Brocade Communications Systems,Inc.
#

from common_driver import vTMDeviceDriverCommon
from neutron_lbaas.common.exceptions import LbaasException
from openstack_connector import OpenStackInterface
from oslo.config import cfg
from oslo_log import log as logging
from vtm import vTM
from time import sleep
from traceback import format_exc

LOG = logging.getLogger(__name__)


class BrocadeAdxDeviceDriverV2(vTMDeviceDriverCommon):
    """
    Shared vTM Cluster Version
    """

    def __init__(self, plugin):
        self.openstack_connector = OpenStackInterface()
        # Build a list of all vTMs in the cluster
        self.vtms = [
            vTM(
                "https://%s:%s/api/tm/%s" % (
                    server,
                    cfg.CONF.vtm_settings.rest_port,
                    cfg.CONF.vtm_settings.api_version
                ),
                cfg.CONF.vtm_settings.username,
                cfg.CONF.vtm_settings.password
            )
            for server in cfg.CONF.lbaas_settings.admin_servers
        ]
        LOG.info(
            _("\nShared Brocade vTM LBaaS module initialized with %s " % len(
                self.vtms
            ) + "cluster members.\nPlease restart the Neutron "
                "server if you manually add/remove any vTMs from the cluster."
            ))

#################
# LOADBALANCERS #
#################

    def create_loadbalancer(self, lb):
        LOG.debug(_("\ncreate_loadbalancer(%s): called" % lb.id))
        self.update_loadbalancer(lb, None)
        LOG.debug(_("\ncreate_loadbalancer(%s): completed!" % lb.id))

    def update_loadbalancer(self, lb, old):
        """
        Creates or updates a TrafficIP group for the loadbalancer VIP address.
        The VIP is added to the allowed_address_pairs of the ports of each
        vTM cluster member to enable them to receive traffic.
        """
        LOG.debug(_("\nupdate_loadbalancer(%s): called" % lb.id))
        try:
            vtm = self._get_vtm()
            # Create a Traffic IP group for the loadbalancer's VIP address
            tip_group_nodes = self._get_tip_group_nodes(vtm)
            tip_config = {"properties": {
                "basic": {
                    "enabled": lb.admin_state_up,
                    "ipaddresses": [lb.vip_address],
                    "machines": tip_group_nodes['machines'],
                    "slaves": tip_group_nodes['passive'],
                    "note": "%s (%s)" % (lb.name, lb.tenant_id)
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
            LOG.debug(_("\nupdate_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in update_loadbalancer(%s): %s" % (
                lb.id, e
            )))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

    def delete_loadbalancer(self, lb):
        """
        Deletes the TrafficIP group for the loadbalancer VIP address.
        The VIP is removed from the allowed_address_pairs of the ports of each
        vTM cluster member.
        """
        LOG.debug(_("\ndelete_loadbalancer(%s): called" % lb.id))
        try:
            vtm = self._get_vtm()
            # Delete the Traffic IP group for the loadbalancer's VIP address
            vtm.tip_group.delete(lb.id)
            # Delete IP from each vTM's "allowed-address-pairs"
            self.openstack_connector.delete_ip_from_ports(
                lb.vip_address, cfg.CONF.lbaas_settings.ports
            )
            LOG.debug(_("\ndelete_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in delete_loadbalancer(%s): %s" % (
                lb.id, e
            )))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

#############
# LISTENERS #
#############

    def update_listener(self, listener, old):
        """
        Creates or updates a Virtual Server bound to the listener port.
        The IP address is that of the specified "loadbalancer", i.e.
        TrafficIP.
        Connection limiting is implemented using a Rate Class and a
        corresponding TrafficScript request rule.
        """
        LOG.debug(_("\nupdate_listener(%s): called" % listener.id))
        try:
            vtm = self._get_vtm()
            listen_on_settings = {}
            listen_on_settings['listen_on_traffic_ips'] = [
                listener.loadbalancer.id
            ]
            listen_on_settings['listen_on_any'] = False
            super(BrocadeAdxDeviceDriverV2, self).update_listener(
                listener, old, vtm, listen_on_settings, False,
                "%s (%s)" % (listener.name, listener.tenant_id)
            )
            LOG.debug(_("\nupdate_listener(%s): completed" % listener.id))
        except Exception as e:
            LOG.error(
                _("\nError in update_listener(%s): %s" % (listener.id, e))
            )
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

    def delete_listener(self, listener):
        """
        Deletes the Virtual Server associated with the listener.
        Also cleans up any associated Rate Classes and TrafficScript rules.
        """
        LOG.debug(_("\ndelete_listener(%s): called" % listener.id))
        try:
            vtm = self._get_vtm()
            super(BrocadeAdxDeviceDriverV2, self).delete_listener(
                listener, vtm, False
            )
            LOG.debug(_("\ndelete_listener(%s): completed" % listener.id))
        except Exception as e:
            LOG.error(
                _("\nError in delete_listener(%s): %s" % (listener.id, e))
            )
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

#########
# POOLS #
#########

    def update_pool(self, pool, old):
        """
        Creates or updates a Pool of servers.
        Session persistence is implemented using Session Persistence Classes.
        If SOURCE_IP is selected as the loadbalancing algorithm, this will
        override any other session persistence applied.
        """
        LOG.debug(_("\nupdate_pool(%s): called" % pool.id))
        try:
            vtm = self._get_vtm()
            super(BrocadeAdxDeviceDriverV2, self).update_pool(
                pool, old, vtm, "%s (%s)" % (pool.name, pool.tenant_id)
            )
            LOG.debug(_("\nupdate_pool(%s): completed!" % pool.id))
        except Exception as e:
            LOG.error(_("\nError in update_pool(%s): %s" % (pool.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

    def delete_pool(self, pool):
        """
        Deletes the vTM Pool associated with the Neutron pool.
        Also cleans up any associated Session Persistence Classes.
        """
        LOG.debug(_("\ndelete_pool(%s): called" % pool.id))
        try:
            vtm = self._get_vtm()
            super(BrocadeAdxDeviceDriverV2, self).delete_pool(pool, vtm)
            LOG.debug(_("\ndelete_pool(%s): completed!" % pool.id))
        except Exception as e:
            LOG.error(_("\nError in delete_pool(%s): %s" % (pool.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

############
# MONITORS #
############

    def update_healthmonitor(self, monitor, old):
        """
        Creates or updates a Health Monitor.
        """
        LOG.debug(_("\nupdate_healthmonitor(%s): called" % monitor.id))
        try:
            vtm = self._get_vtm()
            super(BrocadeAdxDeviceDriverV2, self).update_healthmonitor(
                monitor, old, vtm,
                "%s (%s)" % (monitor.pool.name, monitor.tenant_id)
            )
            LOG.debug(_("\nupdate_healthmonitor(%s): completed!" % monitor.id))
        except Exception as e:
            LOG.error(
                _("\nError in update_healthmonitor(%s): %s" % (monitor.id, e))
            )
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

    def delete_healthmonitor(self, monitor):
        LOG.debug(_("\ndelete_healthmonitor(%s): called" % monitor.id))
        try:
            vtm = self._get_vtm()
            super(BrocadeAdxDeviceDriverV2, self).delete_healthmonitor(
                monitor, vtm
            )
            LOG.debug(_("\ndelete_healthmonitor(%s): completed!" % monitor.id))
        except Exception as e:
            LOG.error(
                _("\nError in delete_healthmonitor(%s): %s" % (monitor.id, e))
            )
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

#########
# STATS #
#########

    def stats(self, loadbalancer):
        LOG.debug(_("\nstats(%s): called" % loadbalancer.id))
        try:
            vtm = self._get_vtm()
            return super(BrocadeAdxDeviceDriverV2, self).stats(
                vtm, loadbalancer.vip_address
            )
        except Exception as e:
            LOG.error(_("\nError in stats(%s): %s" % (loadbalancer.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

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
