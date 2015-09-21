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

from neutron_lbaas.common.exceptions import LbaasException
from oslo.config import cfg
from oslo_log import log as logging
from vtm import vTM
from driver_unmanaged import BrocadeAdxDeviceDriverV2 \
    as vTMDeviceDriverUnmanaged
from time import sleep
from traceback import format_exc

LOG = logging.getLogger(__name__)


class BrocadeAdxDeviceDriverV2(vTMDeviceDriverUnmanaged):
    """
    Services Director Unmanaged Version with provisioning of HA pairs.
    """

    def create_loadbalancer(self, lb):
        """
        Ensures a vTM cluster is instantiated for the service.
        If the deployment model is PER_LOADBALANCER, a new vTM cluster
        will always be spawned by this call.  If the deployemnt model is
        PER_TENANT, a new cluster will only be spawned if one does not
        already exist for the tenant.
        """
        super(BrocadeAdxDeviceDriverV2, self).create_loadbalancer(lb)
        if self.lb_deployment_model == "PER_LOADBALANCER":
            self.update_loadbalancer(lb, None)

    def update_loadbalancer(self, lb, old):
        LOG.debug(_("\nupdate_loadbalancer(%s): called" % lb.id))
        """
        Creates or updates a TrafficIP group for the loadbalancer VIP address.
        The VIP is added to the allowed_address_pairs of the vTM's
        Neutron port to enable it to receive traffic to this address.
        NB. This only function only has a purpose in PER_TENANT deployments!
        """
        try:
            if self.lb_deployment_model == "PER_TENANT":
                hostnames = self._get_hostname(lb.tenant_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostnames = self._get_hostname(lb.id)
            vtm = self._get_vtm(hostnames)
            tip_config = {"properties": {
                "basic": {
                    "ipaddresses": [lb.vip_address],
                    "machines": vtm.get_nodes_in_cluster(),
                    "note": lb.name
                }
            }}
            vtm.tip_group.create(lb.id, config=tip_config)
            if not old or lb.vip_address != old.vip_address:
                for hostname in hostnames:
                    port_id = self.openstack_connector.get_server_port(
                        lb.tenant_id, hostname
                    )
                    self.openstack_connector.add_ip_to_ports(
                        lb.vip_address, [port_id]
                    )
            LOG.debug(_("\nupdate_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in update_loadbalancer(%s): %s" % (lb.id, e)))
            LOG.trace(_("\n%s" % format_exc()))
            raise LbaasException()

    def delete_loadbalancer(self, lb):
        """
        Deletes the listen IP from a vTM.
        In the case of PER_LOADBALANCER deployments, this involves destroying
        the whole vTM instance. In the case of a PER_TENANT deployment, it
        involves deleting the TrafficIP Group associated with the VIP address.
        When the last TrafficIP Group has been deleted, the instance is
        destroyed.
        """
        LOG.debug(_("\ndelete_loadbalancer(%s): called" % lb.id))
        try:
            if self.lb_deployment_model == "PER_TENANT":
                hostnames = self._get_hostname(lb.tenant_id)
                vtm = self._get_vtm(hostnames)
                vtm.tip_group.delete(lb.id)
                if not vtm.tip_group.list():
                    LOG.debug(
                        _("\ndelete_loadbalancer(%s): "
                        "last loadbalancer deleted; destroying vTM" % lb.id)
                    )
                    self._destroy_vtm(hostnames, lb)
                else:
                    for hostname in hostnames:
                        port_id = self.openstack_connector.get_server_port(
                            lb.tenant_id, hostname
                        )
                        self.openstack_connector.delete_ip_from_ports(
                            lb.vip_address, [port_id]
                        )
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostnames = self._get_hostname(lb.id)
                self._destroy_vtm(hostnames, lb)
            LOG.debug(_("\ndelete_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in delete_loadbalancer(%s): %s" % (lb.id, e)))
            LOG.trace(_("\n%s" % format_exc()))
            raise LbaasException()

########
# MISC #
########

    def _get_hostname(self, id):
        return ("vtm-%s-pri" % (id), "vtm-%s-sec" % (id))

    def _get_vtm(self, hostnames):
        services_director = self._get_services_director()
        for i in xrange(5):
            for hostname in hostnames:
                url = "%s/instance/%s/tm/%s" % (
                    services_director.instance_url,
                    hostname,
                    cfg.CONF.vtm_settings.api_version
                )
                vtm = vTM(
                    url,
                    cfg.CONF.services_director_settings.username,
                    cfg.CONF.services_director_settings.password
                )
                try:
                    if not vtm.test_connectivity():
                        raise Exception("")
                    return vtm
                except Exception:
                    pass
            sleep(i)
        raise Exception("Could not contact either vTM instance in cluster")

    def _spawn_vtm(self, hostnames, lb):
        """
        Creates a vTM HA cluster as Nova VM instances.
        The VMs are registered with Services Director to provide licensing and
        configuration proxying.
        """
        services_director = self._get_services_director()
        cluster = self.openstack_connector.create_vtms(hostnames, lb)
        LOG.info(_("\nvTMs %s created for tenant %s" % (
            hostnames, lb.tenant_id
        )))
        for member in cluster['nodes']:
            instance = services_director.unmanaged_instance.create(
                "%s-%s" % (lb.id, member['hostname']),
                tag=member['hostname'],
                admin_username=cfg.CONF.vtm_settings.username,
                admin_password=cluster['password'],
                management_address=member['mgmt_ip'],
                rest_address="%s:%s" % (
                    member['mgmt_ip'], cfg.CONF.vtm_settings.rest_port
                ),
                owner=lb.tenant_id,
                bandwidth=cfg.CONF.services_director_settings.bandwidth,
                stm_version=cfg.CONF.services_director_settings.
                            version_resource,
                stm_feature_pack=cfg.CONF.services_director_settings.
                                 feature_pack
            )
            instance.start()
            LOG.debug(
                _("\nvTM %s registered with Services Director" % (
                    member['hostname']
                )))
            url = "%s/instance/%s/tm/%s" % (
                services_director.instance_url,
                member['hostname'],
                cfg.CONF.vtm_settings.api_version
            )
            sa = vTM(
                url,
                cfg.CONF.services_director_settings.username,
                cfg.CONF.services_director_settings.password
            )
            for counter in xrange(15):
                try:
                    if not sa.test_connectivity():
                        raise Exception("")
                    break
                except Exception:
                    pass
                if counter == 14:
                    raise Exception(
                        "vTM instance %s failed to boot... Timed out." % (
                            member['hostname']
                        ))
                sleep(10)

    def _destroy_vtm(self, hostnames, lb):
        """
        Destroys the vTM Nova VM.
        The vTM is "deleted" in Services Director (this flags the instance
        rather than actually deleting it from the database).
        """
        services_director = self._get_services_director()
        for hostname in hostnames:
            try:
                self.openstack_connector.destroy_vtm(hostname, lb)
                LOG.debug(_("\nvTM %s destroyed" % hostname))
                services_director.unmanaged_instance.delete(hostname)
                LOG.debug(_("\nInstance %s deactivated" % hostname))
            except Exception as e:
                LOG.error(_(e))
