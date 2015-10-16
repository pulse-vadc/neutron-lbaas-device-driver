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
from services_director import ServicesDirector
from vtm import vTM
from time import sleep
from traceback import format_exc

LOG = logging.getLogger(__name__)


class BrocadeAdxDeviceDriverV2(vTMDeviceDriverCommon):
    """
    Services Director Unmanaged Version
    """

    def __init__(self, plugin):
        self.lb_deployment_model = cfg.CONF.lbaas_settings.deployment_model
        if cfg.CONF.lbaas_settings.admin_ips is not None:
            services_director_list = cfg.CONF.lbaas_settings.admin_ips
        else:
            services_director_list = cfg.CONF.lbaas_settings.admin_servers
        self.services_directors = [
            ServicesDirector(
                "https://%s:%s/api/tmcm/%s" % (
                    server,
                    cfg.CONF.services_director_settings.rest_port,
                    cfg.CONF.services_director_settings.api_version
                ),
                cfg.CONF.services_director_settings.username,
                cfg.CONF.services_director_settings.password,
                connectivity_test_url="https://%s:%s/api/tmcm/1.5" % (
                    server,
                    cfg.CONF.services_director_settings.rest_port
                )
            )
            for server in services_director_list
        ]
        self.openstack_connector = OpenStackInterface()
        LOG.info(_("\nBrocade vTM LBaaS module initialized."))

    def create_loadbalancer(self, lb):
        """
        Ensures a vTM instance is instantiated for the service.
        If the deployment model is PER_LOADBALANCER, a new vTM instance
        will always be spawned by this call.  If the deployemnt model is
        PER_TENANT, a new instance will only be spawned if one does not
        already exist for the tenant.
        """
        LOG.debug(_("\ncreate_loadbalancer(%s): called" % lb.id))
        try:
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(lb.tenant_id)
                if not self.openstack_connector.vtm_exists(
                    lb.tenant_id, hostname):
                    self._spawn_vtm(hostname, lb)
                    sleep(5)
                self.update_loadbalancer(lb, None)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(lb.id)
                self._spawn_vtm(hostname, lb)
            LOG.debug(_("\ncreate_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in create_loadbalancer(%s): %s" % (lb.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

    def update_loadbalancer(self, lb, old):
        """
        Creates or updates a TrafficIP group for the loadbalancer VIP address.
        The VIP is added to the allowed_address_pairs of the vTM's
        Neutron port to enable it to receive traffic to this address.
        NB. This only function only has a purpose in PER_TENANT deployments!
        """
        LOG.debug(_("\nupdate_loadbalancer(%s): called" % lb.id))
        try:
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(lb.tenant_id)
                vtm = self._get_vtm(hostname)
                tip_config = {"properties": {
                    "basic": {
                        "ipaddresses": [lb.vip_address],
                        "machines": vtm.get_nodes_in_cluster(),
                        "note": lb.name
                    }
                }}
                vtm.tip_group.create(lb.id, config=tip_config)
                if not old or lb.vip_address != old.vip_address:
                    port_id = self.openstack_connector.get_server_port(
                        lb.tenant_id, hostname
                    )
                    self.openstack_connector.add_ip_to_ports(
                        lb.vip_address, [port_id]
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
                hostname = self._get_hostname(lb.tenant_id)
                vtm = self._get_vtm(hostname)
                vtm.tip_group.delete(lb.id)
                if not vtm.tip_group.list():
                    LOG.debug(_(
                        "\ndelete_loadbalancer(%s): "
                        "last loadbalancer deleted; destroying vTM" % lb.id
                    ))
                    self._destroy_vtm(hostname, lb)
                else:
                    port_id = self.openstack_connector.get_server_port(
                        lb.tenant_id, hostname
                    )
                    self.openstack_connector.delete_ip_from_ports(
                        lb.vip_address, [port_id]
                    )
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(lb.id)
                self._destroy_vtm(hostname, lb)
            LOG.debug(_("\ndelete_loadbalancer(%s): completed!" % lb.id))
        except Exception as e:
            LOG.error(_("\nError in delete_loadbalancer(%s): %s" % (lb.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

#############
# LISTENERS #
#############

    def update_listener(self, listener, old):
        """
        Creates or updates a Virtual Server bound to the listener port.
        The IP address is that of the specified "loadbalancer", i.e.
        TrafficIP or vTM instance.
        Connection limiting is implemented using a Rate Class and a
        corresponding TrafficScript request rule.
        """
        LOG.debug(_("\nupdate_listener(%s): called" % listener.id))
        try:
            listen_on_settings = {}
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(listener.tenant_id)
                listen_on_settings['listen_on_traffic_ips'] = [
                    listener.loadbalancer.id
                ]
                listen_on_settings['listen_on_any'] = False
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(listener.loadbalancer_id)
                listen_on_settings['listen_on_traffic_ips'] = []
                listen_on_settings['listen_on_any'] = True
            vtm = self._get_vtm(hostname)
            super(BrocadeAdxDeviceDriverV2, self).update_listener(
                listener, old, vtm, listen_on_settings
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
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(listener.tenant_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(listener.loadbalancer_id)
            vtm = self._get_vtm(hostname)
            super(BrocadeAdxDeviceDriverV2, self).delete_listener(
                listener, vtm
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
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(pool.tenant_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(pool.listener.loadbalancer_id)
            vtm = self._get_vtm(hostname)
            super(BrocadeAdxDeviceDriverV2, self).update_pool(
                pool, old, vtm
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
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(pool.tenant_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(pool.listener.loadbalancer_id)
            vtm = self._get_vtm(hostname)
            super(BrocadeAdxDeviceDriverV2, self).delete_pool(
                pool, vtm
            )
            LOG.debug(_("\ndelete_pool(%s): completed!" % pool.id))
        except Exception as e:
            LOG.error(_("\nError in delete_pool(%s): %s" % (pool.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

############
# MONITORS #
############

    def update_healthmonitor(self, monitor, old):
        LOG.debug(_("\nupdate_healthmonitor(%s): called" % monitor.id))
        try:
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(monitor.tenant_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(monitor.root_loadbalancer.id)
            vtm = self._get_vtm(hostname)
            super(BrocadeAdxDeviceDriverV2, self).update_healthmonitor(
                monitor, old, vtm
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
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(monitor.tenant_id)
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(monitor.root_loadbalancer.id)
            vtm = self._get_vtm(hostname)
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
            if self.lb_deployment_model == "PER_TENANT":
                hostname = self._get_hostname(loadbalancer.tenant_id)
                vtm = self._get_vtm(hostname)
                return super(BrocadeAdxDeviceDriverV2, self).stats(
                    vtm, loadbalancer.vip_address
                )
            elif self.lb_deployment_model == "PER_LOADBALANCER":
                hostname = self._get_hostname(loadbalancer.id)
                vtm = self._get_vtm(hostname)
                return super(BrocadeAdxDeviceDriverV2, self).stats(vtm)
        except Exception as e:
            LOG.error(_("\nError in stats(%s): %s" % (loadbalancer.id, e)))
            LOG.error(_("\n%s" % format_exc()))
            raise LbaasException()

########
# MISC #
########

    def _get_services_director(self):
        """
        Gets available instance of Brocade Services Director from the cluster.
        """
        for services_director in self.services_directors:
            if services_director.test_connectivity():
                return services_director
        raise Exception("Could not contact any Services Directors")

    def _get_vtm(self, hostname):
        """
        Gets available instance of Brocade vTM from a Services Director.
        """
        services_director = self._get_services_director()
        url = "%s/instance/%s/tm/%s" % (
            services_director.instance_url,
            hostname,
            cfg.CONF.vtm_settings.api_version
        )
        for i in xrange(5):
            vtm = vTM(
                url,
                cfg.CONF.services_director_settings.username,
                cfg.CONF.services_director_settings.password,
                connectivity_test_url="%s/instance/%s/tm/%s" % (
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

    def _spawn_vtm(self, hostname, lb):
        """
        Creates a vTM instance as a Nova VM.
        The VM is registered with Services Director to provide licensing and
        configuration proxying.
        """
        services_director = self._get_services_director()
        (mgmt_ip, password) = self.openstack_connector.create_vtm(hostname, lb)
        LOG.info(
            _("\nvTM %s created for tenant %s" % (hostname, lb.tenant_id))
        )
        instance = services_director.unmanaged_instance.create(
            lb.id,
            tag=hostname,
            admin_username=cfg.CONF.vtm_settings.username,
            admin_password=password,
            management_address=mgmt_ip,
            rest_address="%s:%s" % (
                mgmt_ip, cfg.CONF.vtm_settings.rest_port
            ),
            rest_enabled=False,
            owner=lb.tenant_id,
            bandwidth=cfg.CONF.services_director_settings.bandwidth,
            stm_version=cfg.CONF.services_director_settings.version_resource,
            stm_feature_pack=cfg.CONF.services_director_settings.feature_pack
        )
        instance.start()
        LOG.debug(_("\nvTM %s registered with Services Director" % hostname))
        url = "%s/instance/%s/tm/%s" % (
            services_director.connectivity_test_url,
            hostname,
            cfg.CONF.vtm_settings.api_version
        )
        vtm = vTM(
            url,
            cfg.CONF.services_director_settings.username,
            cfg.CONF.services_director_settings.password
        )
        for counter in xrange(15):
            try:
                if not vtm.test_connectivity():
                    raise Exception("")
                return vtm
            except Exception:
                pass
            sleep(10)
        raise Exception(
            "vTM instance %s failed to boot... Timed out." % hostname
        )
        instance.rest_enabled = True
        instance.license_name = cfg.CONF.services_director_settings.fla_license
        instance.update()
        sleep(5)  # Needed to ensure TIP Groups are always created

    def _destroy_vtm(self, hostname, lb):
        """
        Destroys the vTM Nova VM.
        The vTM is "deleted" in Services Director (this flags the instance
        rather than actually deleting it from the database).
        """
        self.openstack_connector.destroy_vtm(hostname, lb)
        LOG.debug(_("\nvTM %s destroyed" % hostname))
        services_director = self._get_services_director()
        services_director.unmanaged_instance.delete(lb.id)
        LOG.debug(_("\nInstance %s deactivated" % hostname))
