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
# Matthew Geldert (mgeldert@brocade.com), Brocade Communications Systems,Inc.
#

from driver_common import vTMDeviceDriverCommon, logging_wrapper
from neutron_lbaas.common.exceptions import LbaasException
from oslo_config import cfg
from oslo_log import log as logging
from services_director import ServicesDirector
from threading import Thread
from vtm import vTM
from time import sleep, time
from traceback import format_exc

LOG = logging.getLogger(__name__)


class BrocadeDeviceDriverV2(vTMDeviceDriverCommon):
    """
    Services Director Unmanaged Version
    """

    def __init__(self, plugin):
        self.services_director = ServicesDirector(
            "https://{}:{}/api/tmcm/{}".format(
                cfg.CONF.lbaas_settings.service_endpoint_address,
                cfg.CONF.services_director_settings.rest_port,
                cfg.CONF.services_director_settings.api_version
            ),
            cfg.CONF.services_director_settings.username,
            cfg.CONF.services_director_settings.password,
            connectivity_test_url="https://{}:{}/api/tmcm/1.5".format(
                cfg.CONF.lbaas_settings.service_endpoint_address,
                cfg.CONF.services_director_settings.rest_port
            )
        )
        super(BrocadeDeviceDriverV2, self).__init__()
        LOG.info(_("\nBrocade vTM LBaaS module initialized."))

    @logging_wrapper
    def create_loadbalancer(self, lb):
        """
        Ensures a vTM instance is instantiated for the service.
        If the deployment model is PER_LOADBALANCER, a new vTM instance
        will always be spawned by this call.  If the deployemnt model is
        PER_TENANT, a new instance will only be spawned if one does not
        already exist for the tenant.
        """
        self._assert_not_mgmt_network(lb.vip_subnet_id)
        deployment_model = self._get_setting(
            lb.tenant_id, "lbaas_settings", "deployment_model"
        )
        hostname = self._get_hostname(lb)
        if deployment_model == "PER_TENANT":
            if not self.openstack_connector.vtm_exists(
                lb.tenant_id, hostname):
                self._spawn_vtm(hostname, lb)
                sleep(5)
            elif not self.openstack_connector.vtm_has_subnet_port(hostname,lb):
                vtm = self._get_vtm(hostname)
                self._attach_subnet_port(vtm, hostname, lb)
            self.update_loadbalancer(lb, None)
        elif deployment_model == "PER_LOADBALANCER":
            self._spawn_vtm(hostname, lb)

    @logging_wrapper
    def update_loadbalancer(self, lb, old):
        """
        Creates or updates a TrafficIP group for the loadbalancer VIP address.
        The VIP is added to the allowed_address_pairs of the vTM's
        Neutron port to enable it to receive traffic to this address.
        NB. This only function only has a purpose in PER_TENANT deployments!
        """
        deployment_model = self._get_setting(
            lb.tenant_id, "lbaas_settings", "deployment_model"
        )
        if deployment_model == "PER_TENANT":
            hostname = self._get_hostname(lb)
            vtm = self._get_vtm(hostname)
            tip_config = {"properties": {
                "basic": {
                    "enabled": lb.admin_state_up,
                    "ipaddresses": [lb.vip_address],
                    "machines": vtm.get_nodes_in_cluster(),
                    "note": lb.name
                }
            }}
            vtm.tip_group.create(lb.id, config=tip_config)
            self._touch_last_modified_timestamp(vtm)
            if not old or lb.vip_address != old.vip_address:
                port_ids = self.openstack_connector.get_server_port_ids(
                    lb.tenant_id, hostname
                )
                self.openstack_connector.add_ip_to_ports(
                    lb.vip_address, port_ids
                )

    @logging_wrapper
    def delete_loadbalancer(self, lb):
        """
        Deletes the listen IP from a vTM.
        In the case of PER_LOADBALANCER deployments, this involves destroying
        the whole vTM instance. In the case of a PER_TENANT deployment, it
        involves deleting the TrafficIP Group associated with the VIP address.
        When the last TrafficIP Group has been deleted, the instance is
        destroyed.
        """
        deployment_model = self._get_setting(
            lb.tenant_id, "lbaas_settings", "deployment_model"
        )
        hostname = self._get_hostname(lb)
        if deployment_model == "PER_TENANT":
            vtm = self._get_vtm(hostname)
            vtm.tip_group.delete(lb.id)
            self._touch_last_modified_timestamp(vtm)
            if not vtm.tip_group.list():
                LOG.debug(_(
                    "\ndelete_loadbalancer({}): "
                    "last loadbalancer deleted; destroying vTM".format(lb.id)
                ))
                self._destroy_vtm(hostname, lb)
            else:
                # Delete subnet port if subnet no longer required
                if self.openstack_connector.subnet_in_use(lb) is False:
                    self._detach_subnet_port(vtm, hostname, lb)
                # Remove allowed_address_pairs entry from remaining ports
                port_ids = self.openstack_connector.get_server_port_ids(
                    lb.tenant_id, hostname
                )
                self.openstack_connector.delete_ip_from_ports(
                    lb.vip_address, port_ids
                )
        elif deployment_model == "PER_LOADBALANCER":
            self._destroy_vtm(hostname, lb)

#############
# LISTENERS #
#############

    @logging_wrapper
    def update_listener(self, listener, old):
        listen_on_settings = {}
        deployment_model = self._get_setting(
            listener.tenant_id, "lbaas_settings", "deployment_model"
        )
        hostname = self._get_hostname(listener.loadbalancer)
        if deployment_model == "PER_TENANT":
            listen_on_settings['listen_on_traffic_ips'] = [
                listener.loadbalancer.id
            ]
            listen_on_settings['listen_on_any'] = False
        elif deployment_model == "PER_LOADBALANCER":
            listen_on_settings['listen_on_traffic_ips'] = []
            listen_on_settings['listen_on_any'] = True
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).update_listener(
            listener, old, vtm, listen_on_settings
        )
        self._touch_last_modified_timestamp(vtm)

    @logging_wrapper
    def delete_listener(self, listener):
        deployment_model = self._get_setting(
            listener.tenant_id, "lbaas_settings", "deployment_model"
        )
        hostname = self._get_hostname(listener.loadbalancer)
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).delete_listener(listener, vtm)
        self._touch_last_modified_timestamp(vtm)

#########
# POOLS #
#########

    @logging_wrapper
    def update_pool(self, pool, old):
        deployment_model = self._get_setting(
            pool.tenant_id, "lbaas_settings", "deployment_model"
        )
        if deployment_model == "PER_TENANT":
            hostname = self._get_hostname(pool.root_loadbalancer)
        elif deployment_model == "PER_LOADBALANCER":
            if pool.loadbalancer is not None:
                hostname = self._get_hostname(pool.loadbalancer)
            else:
                hostname = self._get_hostname(
                    pool.listener.loadbalancer
                )
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).update_pool(pool, old, vtm)
        self._touch_last_modified_timestamp(vtm)

    @logging_wrapper
    def delete_pool(self, pool):
        hostname = self._get_hostname(pool.loadbalancer)
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).delete_pool(
            pool, vtm
        )
        self._touch_last_modified_timestamp(vtm)

############
# MONITORS #
############

    @logging_wrapper
    def update_healthmonitor(self, monitor, old):
        hostname = self._get_hostname(
            monitor.root_loadbalancer
        )
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).update_healthmonitor(
            monitor, old, vtm
        )
        self._touch_last_modified_timestamp(vtm)

    @logging_wrapper
    def delete_healthmonitor(self, monitor):
        hostname = self._get_hostname(monitor.root_loadbalancer)
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).delete_healthmonitor(
            monitor, vtm
        )
        self._touch_last_modified_timestamp(vtm)

###############
# L7 POLICIES #
###############

    @logging_wrapper
    def update_l7_policy(self, policy, old):
        hostname = self._get_hostname(policy.root_loadbalancer)
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).update_l7_policy(policy, old, vtm)
        self._touch_last_modified_timestamp(vtm)

    @logging_wrapper
    def delete_l7_policy(self, policy):
        hostname = self._get_hostname(policy.root_loadbalancer)
        vtm = self._get_vtm(hostname)
        super(BrocadeDeviceDriverV2, self).delete_l7_policy(policy, vtm)
        self._touch_last_modified_timestamp(vtm)

#########
# STATS #
#########

    @logging_wrapper
    def stats(self, loadbalancer):
        deployment_model = self._get_setting(
            loadbalancer.tenant_id, "lbaas_settings", "deployment_model"
        )
        hostname = self._get_hostname(loadbalancer)
        vtm = self._get_vtm(hostname)
        if deployment_model == "PER_TENANT":
            return super(BrocadeDeviceDriverV2, self).stats(
                vtm, loadbalancer.vip_address
            )
        elif self.lb_deployment_model == "PER_LOADBALANCER":
            return super(BrocadeDeviceDriverV2, self).stats(vtm)

########
# MISC #
########

    def _touch_last_modified_timestamp(self, vtm):
        timestamp = str(int(time() * 1000))
        vtm.extra_file.create("last_update", file_text=timestamp)

    def _get_hostname(self, lb):
        identifier = self.openstack_connector.get_identifier(lb)
        return "vtm-{}".format(identifier)

    def _get_services_director(self):
        """
        Gets available instance of Brocade Services Director from the cluster.
        """
        for _ in range(3):
            if self.services_director.test_connectivity():
                return self.services_director
        raise Exception("Could not contact Services Director")

    def _get_vtm(self, hostname):
        """
        Gets available instance of Brocade vTM from a Services Director.
        """
        if isinstance(hostname, list) or isinstance(hostname, tuple):
            for host in hostname:
                try:
                    return self._get_vtm(host)
                except:
                    pass
            raise Exception("Could not contact vTM instance")
        services_director = self._get_services_director()
        url = "{}/instance/{}/tm/{}".format(
            services_director.instance_url,
            hostname,
            cfg.CONF.vtm_settings.api_version
        )
        for i in xrange(5):
            vtm = vTM(
                url,
                cfg.CONF.services_director_settings.username,
                cfg.CONF.services_director_settings.password,
                connectivity_test_url="{}/instance/{}/tm/{}".format(
                    services_director.connectivity_test_url,
                    hostname,
                    cfg.CONF.vtm_settings.api_version
                )
            )
            try:
                if not vtm.test_connectivity():
                    raise Exception("")
                return vtm
            except:
                pass
            sleep(i)
        raise Exception("Could not contact vTM instance")

    def _assert_not_mgmt_network(self, subnet_id):
        network_id = self.openstack_connector.get_network_for_subnet(subnet_id)
        if network_id == cfg.CONF.lbaas_settings.management_network:
            raise Exception("Specified subnet is part of management network")

    def _attach_subnet_port(self, vtm, hostname, lb):
        # Create and attach a new Neutron port to the instance
        port = self.openstack_connector.attach_port(hostname, lb)
        # Configure the interface on the vTM
        mgmt_ip = self.openstack_connector.get_mgmt_ip(lb.tenant_id, hostname)
        tm_settings = vtm.traffic_manager.get(mgmt_ip)
        iface_list = tm_settings.appliance__if
        # Calculate the interface name that will be used
        used_iface_numbers = sorted([
            int(iface['name'][3:]) for iface in iface_list
        ])
        next_if = None
        for i, iface in enumerate(used_iface_numbers):
            if iface > i:
                next_if = "eth{}".format(i)
                break
        if next_if is None:
            next_if = "eth{}".format(len(iface_list))
        # Configure the interface on the vTM
        tm_settings.appliance__if.append({
            "name": next_if,
            "mtu": cfg.CONF.vtm_settings.mtu
        })
        tm_settings.appliance__ip.append({
            "name": next_if,
            "addr": port['fixed_ips'][0]['ip_address'],
            "mask": self.openstack_connector.get_subnet_netmask(
                lb.vip_subnet_id),
            "isexternal":False
        })
        tm_settings.update()
        # Configure return-path routing for the new port
        ip, mac = self.openstack_connector.get_subnet_gateway(
            lb.vip_subnet_id
        )
        if ip is not None and mac is not None:
            return_paths = vtm.global_settings.ip__appliance_returnpath
            if {"mac": mac, "ipv4": ip} not in return_paths:
                return_paths.append({"mac": mac, "ipv4": ip})
                vtm.global_settings.ip__appliance_returnpath = return_paths
                vtm.global_settings.update()

    def _detach_subnet_port(self, vtm, hostname, lb):
        # Detach and delete Neutron port from the instance
        port_ip_address = self.openstack_connector.detach_port(hostname, lb)
        mgmt_ip = self.openstack_connector.get_mgmt_ip(lb.tenant_id, hostname)
        tm_settings = vtm.traffic_manager.get(mgmt_ip)
        # Get the name of the interface to delete
        iface_list = tm_settings.appliance__ip
        iface_to_delete = None
        for iface in iface_list:
            if iface['addr'] == port_ip_address:
                iface_to_delete = iface['name']
                break
        if iface_to_delete is None:
            raise Exception(_("No interface configuration found"))
        # Delete the "ip" entry for the interface
        new_iface_list = [
            iface for iface in iface_list
            if iface['name'] != iface_to_delete
        ]
        tm_settings.appliance__ip = new_iface_list
        # Delete the "if" entry for the interface
        iface_list = tm_settings.appliance__if
        new_iface_list = [
            iface for iface in iface_list if iface['name'] != iface_to_delete
        ]
        tm_settings.appliance__if = new_iface_list
        tm_settings.update()
        # Remove return-path routing for the old port
        ip, mac = self.openstack_connector.get_subnet_gateway(
            lb.vip_subnet_id
        )
        return_paths = vtm.global_settings.ip__appliance_returnpath
        new_return_paths = [
            return_path for return_path in return_paths
            if return_path['mac'] != mac and return_path['ipv4'] != ip
        ]
        vtm.global_settings.ip__appliance_returnpath = new_return_paths
        vtm.global_settings.update()

    def _spawn_vtm(self, hostname, lb):
        """
        Creates a vTM instance as a Nova VM.
        The VM is registered with Services Director to provide licensing and
        configuration proxying.
        """
        # Initialize lists for roll-back on error
        port_ids = []
        security_groups = []
        vms = []
        # Create password and ports...
        try: # For rolling back objects if an error occurs
            password = self._generate_password()
            if cfg.CONF.lbaas_settings.management_mode == "FLOATING_IP":
                port, sec_grp, mgmt_ip = self.openstack_connector.create_port(
                    lb, hostname, create_floating_ip=True
                )
                ports = {"data": port, "mgmt": None}
                port_ids.append(port['id'])
                security_groups = [sec_grp]
            elif cfg.CONF.lbaas_settings.management_mode == "MGMT_NET":
                data_port, sec_grp,junk = self.openstack_connector.create_port(
                    lb, hostname
                )
                (mgmt_port, mgmt_sec_grp, mgmt_ip) = self.openstack_connector.create_port(
                    lb, hostname, mgmt_port=True
                )
                ports = {"data": data_port, "mgmt": mgmt_port}
                security_groups = [sec_grp, mgmt_sec_grp]
                port_ids.append(data_port['id'])
                port_ids.append(mgmt_port['id'])
            # Register instance record...
            bandwidth = self._get_setting(
                lb.tenant_id, "services_director_settings", "bandwidth"
            )
            feature_pack = self._get_setting(
                lb.tenant_id, "services_director_settings", "feature_pack"
            )
            services_director = self._get_services_director()
            instance = services_director.unmanaged_instance.create(
                lb.id,
                tag=hostname,
                admin_username=cfg.CONF.vtm_settings.username,
                admin_password=password,
                management_address=mgmt_ip,
                rest_address="{}:{}".format(
                    mgmt_ip, cfg.CONF.vtm_settings.rest_port
                ),
                rest_enabled=False,
                owner=lb.tenant_id,
                bandwidth=int(bandwidth),
                stm_feature_pack=feature_pack
            )
            instance.start()
            LOG.debug(_(
                "\nvTM {} registered with Services Director".format(hostname)
            ))
            # Start instance...
            vm = self.openstack_connector.create_vtm(hostname, lb, password, ports)
            vms.append(vm['id'])
            LOG.info(
                _("\nvTM {} created for tenant {}".format(
                    hostname, lb.tenant_id
                ))
            )
            poll_thread = PollInstance(instance, hostname, services_director)
            poll_thread.start()
            if poll_thread.join() is False:
                raise Exception(
                    "vTM instance {} failed to boot... Timed out".format(
                        hostname
                    )
                )
        except Exception as e:
            try:
                services_director.unmanaged_instance.delete(hostname)
            except:
                pass
            self.openstack_connector.clean_up(
                lb.tenant_id,
                instances=vms,
                security_groups=security_groups,
                ports=port_ids
            )
            raise e

    def _destroy_vtm(self, hostname, lb):
        """
        Destroys the vTM Nova VM.
        The vTM is "deleted" in Services Director (this flags the instance
        rather than actually deleting it from the database).
        """
        self.openstack_connector.destroy_vtm(hostname, lb)
        LOG.debug(_("\nvTM {} destroyed".format(hostname)))
        services_director = self._get_services_director()
        services_director.unmanaged_instance.delete(hostname)
        LOG.debug(_("\nInstance {} deactivated".format(hostname)))


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
        url = "{}/instance/{}/tm/{}".format(
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
                if not vtm.test_uuid_set():
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
