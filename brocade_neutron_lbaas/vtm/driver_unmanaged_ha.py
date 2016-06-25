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
from threading import Thread
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
                hostnames = self._get_hostname(lb.vip_subnet_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostnames = self._get_hostname(lb.id)
            vtm = self._get_vtm(hostnames)
            cluster_nodes = vtm.get_nodes_in_cluster()
            tip_config = {"properties": {
                "basic": {
                    "enabled": lb.admin_state_up,
                    "ipaddresses": [lb.vip_address],
                    "machines": cluster_nodes,
                    "slaves": [
                        slave for slave in cluster_nodes 
                        if slave.endswith("-sec")
                    ],
                    "note": lb.name
                }
            }}
            vtm.tip_group.create(lb.id, config=tip_config)
            self._touch_last_modified_timestamp(vtm)
            if not old or lb.vip_address != old.vip_address:
                for hostname in hostnames:
                    port_ids = self.openstack_connector.get_server_port_ids(
                        hostname
                    )
                    self.openstack_connector.add_ip_to_ports(
                        lb.vip_address, port_ids
                    )
            LOG.debug(_("\nupdate_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in update_loadbalancer(%s): %s" % (lb.id, e)))
            LOG.error(_("\n%s" % format_exc()))
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
                hostnames = self._get_hostname(lb.vip_subnet_id)
                vtm = self._get_vtm(hostnames)
                vtm.tip_group.delete(lb.id)
                self._touch_last_modified_timestamp(vtm)
                if not vtm.tip_group.list():
                    LOG.debug(
                        _("\ndelete_loadbalancer(%s): "
                        "last loadbalancer deleted; destroying vTM" % lb.id)
                    )
                    self._destroy_vtm(hostnames, lb)
                else:
                    # Delete subnet ports if no longer required
                    if self.openstack_connector.subnet_in_use(lb) is False:
                        self._detach_subnet_port(vtm, hostnames, lb)
                    for hostname in hostnames:
                        port_ids = self.openstack_connector.get_server_port_ids(
                            hostname
                        )
                        self.openstack_connector.delete_ip_from_ports(
                            lb.vip_address, port_ids
                        )
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostnames = self._get_hostname(lb.id)
                self._destroy_vtm(hostnames, lb)
            LOG.debug(_("\ndelete_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in delete_loadbalancer(%s): %s" % (lb.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

########
# MISC #
########

    def _get_hostname(self, id):
        return ("vtm-%s-pri" % (id), "vtm-%s-sec" % (id))

    def _attach_subnet_port(self, vtm, hostnames, lb):
        try:
            for hostname in hostnames:
                super(BrocadeAdxDeviceDriverV2, self)._attach_subnet_port(
                    vtm, hostname, lb
                )
        except AttributeError:
            for hostname in hostnames:
                try:
                    super(BrocadeAdxDeviceDriverV2, self)._detach_subnet_port(
                        vtm, hostname, lb
                    )
                except:
                    pass
            raise Exception(
                "Failed to add new port to vTMs {} - one of the instances "
                "may be down.".format(hostnames)
            )

    def _detach_subnet_port(self, vtm, hostnames, lb):
        for hostname in hostnames:
            super(BrocadeAdxDeviceDriverV2, self)._detach_subnet_port(
                vtm, hostname, lb
            )

    def _spawn_vtm(self, hostnames, lb):
        """
        Creates a vTM HA cluster as Nova VM instances.
        The VMs are registered with Services Director to provide licensing and
        configuration proxying.
        """
        services_director = self._get_services_director()

        # Create password and ports...
        password = self._generate_password()
        ports = {}
        port_ids = []
        security_groups = []
        vms = []
        if cfg.CONF.lbaas_settings.management_mode == "FLOATING_IP":
            # Primary data port (floating IP)
            (port, sec_grp, mgmt_ip) = self.openstack_connector.create_port(
                lb, hostnames[0], create_floating_ip=True, cluster=True
            )
            ports[hostnames[0]] = {
                "ports": {
                    "data": port,
                    "mgmt": None
                },
                "mgmt_ip": mgmt_ip,
                "cluster_ip": port['port']['fixed_ips'][0]['ip_address']
            }
            port_ids.append(port['id'])
            security_groups = [sec_grp]
            # Secondary data port (floating IP)
            (port, junk, mgmt_ip) = self.openstack_connector.create_port(
                lb, hostnames[1], security_group=sec_grp,
                create_floating_ip=True, cluster=True
            )
            ports[hostnames[1]] = {
                "ports": {
                    "data": port,
                    "mgmt": None
                },
                "mgmt_ip": mgmt_ip,
                "cluster_ip": port['port']['fixed_ips'][0]['ip_address']
            }
            port_ids.append(port['id'])
        elif cfg.CONF.lbaas_settings.management_mode == "MGMT_NET":
            # Primary data port (management network)
            (data_port, data_sec_grp, junk) = self.openstack_connector.create_port(
                lb, hostnames[0], cluster=True
            )
            # Primary mgmt port (management network)
            (mgmt_port, mgmt_sec_grp, mgmt_ip) = self.openstack_connector.create_port(
                lb, hostnames[0], mgmt_port=True, cluster=True
            )
            ports[hostnames[0]] = {
                "ports": {
                    "data": data_port,
                    "mgmt": mgmt_port
                },
                "mgmt_ip": mgmt_ip,
                "cluster_ip": mgmt_ip
            }
            security_groups = [data_sec_grp, mgmt_sec_grp]
            port_ids.append(data_port['id'])
            port_ids.append(mgmt_port['id'])
            # Secondary data port (management network)
            (data_port, sec_grp, junk) = self.openstack_connector.create_port(
                lb, hostnames[1], security_group=data_sec_grp, cluster=True
            )
            # Secondary mgmt port (management network)
            (mgmt_port, junk, mgmt_ip) = self.openstack_connector.create_port(
                lb, hostnames[1], mgmt_port=True, security_group=mgmt_sec_grp,
                cluster=True
            )
            ports[hostnames[1]] = {
                "ports": {
                    "data": data_port,
                    "mgmt": mgmt_port
                },
                "mgmt_ip": mgmt_ip,
                "cluster_ip": mgmt_ip
            }
            port_ids.append(data_port['id'])
            port_ids.append(mgmt_port['id'])

        cluster_data = {
            "is_primary": True,
            "peer_name": hostnames[1],
            "peer_addr": ports[hostnames[1]]['cluster_ip']
        }
        avoid = None
        poll_threads = {}
        for host in hostnames:
            instance = services_director.unmanaged_instance.create(
                "%s-%s" % (lb.id, host),
                tag=host,
                admin_username=cfg.CONF.vtm_settings.username,
                admin_password=password,
                management_address=ports[host]['mgmt_ip'],
                rest_address="%s:%s" % (
                    ports[host]['mgmt_ip'], cfg.CONF.vtm_settings.rest_port
                ),
                rest_enabled=False,
                owner=lb.tenant_id,
                bandwidth=cfg.CONF.services_director_settings.bandwidth,
                stm_feature_pack=cfg.CONF.services_director_settings.
                                 feature_pack
            )
            instance.start()
            LOG.debug(
                _("\nvTM %s registered with Services Director" % (host))
            )
            # Launch vTM...
            vm = self.openstack_connector.create_vtm(
                host, lb, password, ports[host]['ports'], cluster_data, avoid
            )
            vms.append(vm['id'])
            # Set params for next iteration...
            if cfg.CONF.lbaas_settings.allow_different_host_hint is True:
                avoid = vm['id']
            cluster_data = {
                "is_primary": False,
                "peer_name": hostnames[0],
                "peer_addr": ports[hostnames[0]]['cluster_ip']
            }
            poll_threads[host] = PollInstance(instance, host, services_director)
            poll_threads[host].start()
        for host, poll_thread in poll_threads.iteritems():
            if poll_thread.join() is False:
                try:
                    services_director.unmanaged_instance.delete(
                        hostnames[0]
                    )
                except:
                    pass
                try:
                    services_director.unmanaged_instance.delete(
                        hostnames[1]
                    )
                except:
                     pass
                self.openstack_connector.clean_up(
                    instances=vms,
                    security_groups=security_groups,
                    ports=port_ids
                )
                raise Exception(
                    "vTM instance %s failed to boot... Timed out" % (host)
                )

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


class PollInstance(Thread):
    class ConnectivityTestFailedError(Exception):
        pass

    def __init__(self, instance, hostname, services_director, *args, **kwargs):
        self.instance = instance
        self.hostname = hostname
        self.services_director = services_director
        self._return = False
        super(PollInstance, self).__init__(*args, **kwargs)
        
    def run(self):
       # Poll for completion of initial configuration...
        url = "%s/instance/%s/tm/%s" % (
            self.services_director.connectivity_test_url,
            self.hostname,
            cfg.CONF.vtm_settings.api_version
        )
        vtm = vTM(
            url,
            cfg.CONF.services_director_settings.username,
            cfg.CONF.services_director_settings.password
        )
        for counter in xrange(100):
            try:
                if not vtm.test_connectivity():
                    raise self.ConnectivityTestFailedError()
                self.instance.rest_enabled = True
                self.instance.license_name = \
                    cfg.CONF.services_director_settings.fla_license
                self.instance.update()
                sleep(5)  # Needed to ensure TIP groups are always created
                self._return = True
                break
            except self.ConnectivityTestFailedError:
                pass
            sleep(5)

    def join(self):
        super(PollInstance, self).join()
        return self._return
