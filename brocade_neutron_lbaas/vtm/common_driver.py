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

from neutron_lbaas.common.cert_manager import _CERT_MANAGER_PLUGIN
from neutron_lbaas.common.tls_utils.cert_parser import get_host_names
from oslo.config import cfg
from oslo_log import log as logging
from random import choice, randint
from string import ascii_letters, digits

LOG = logging.getLogger(__name__)
certificate_manager = _CERT_MANAGER_PLUGIN.CertManager


class vTMDeviceDriverCommon(object):
    """
    Common methods/properties
    """

    PROTOCOL_MAP = {
        "HTTP": "http",
        "HTTPS": "https",
        "TCP": "client_first",
        "TERMINATED_HTTPS": "http",
        "UDP": "udp"
    }

    LB_ALGORITHM_MAP = {
        "ROUND_ROBIN": "weighted_round_robin",
        "LEAST_CONNECTIONS": "weighted_least_connections",
        "SOURCE_IP": "weighted_round_robin"
    }

    PERSISTENCE_MAP = {
        "SOURCE_IP": "ip",
        "APP_COOKIE": "cookie",
        "HTTP_COOKIE": "transparent"
    }

    MONITOR_MAP = {
        "PING": "ping",
        "HTTP": "http",
        "HTTPS": "http",
        "TCP": "connect"
    }

#############
# LISTENERS #
#############

    def create_listener(self, listener):
        self.update_listener(listener, None)

    def update_listener(self, listener, old, vtm, listen_on_settings,
                        use_security_group=True, note=None):
        vserver_config = {"properties": {
            "basic": {
                "enabled": listener.admin_state_up,
                "note": note or listener.name,
                "pool": listener.default_pool_id or "discard",
                "port": listener.protocol_port,
                "protocol": self.PROTOCOL_MAP[listener.protocol]
            }
        }}
        vserver_config['properties']['basic'].update(listen_on_settings)
        # Configure SSL termination...
        if listener.protocol == "TERMINATED_HTTPS":
            if cfg.CONF.lbaas_settings.https_offload is False:
                raise Exception("HTTPS termination has been disabled by "
                                "the administrator")
            # Get cert from Barbican and upload to vTM
            self._upload_certificate(vtm, listener.default_tls_container_id)
            # certificate and initialize the SNI mapping table
            vserver_config['properties']['basic']['ssl_decrypt'] = True
            vserver_config['properties']['ssl'] = {
                "ssl_cert_default": listener.default_tls_container_id,
                "server_cert_host_mapping": []
            }
            if listener.sni_containers:
                for sni_container in listener.sni_containers:
                    # Get cert from Barbican and upload to vTM
                    cert = self._upload_certificate(
                        vtm, sni_container.tls_container_id
                    )
                    # Get CN and subjectAltNames from certificate
                    cert_hostnames = get_host_names(cert.get_certificate())
                    # Add the CN and the certificate to the virtual server
                    # SNI certificate mapping table
                    (vserver_config['properties']['ssl']
                                   ['server_cert_host_mapping']).append(
                        {
                            "host": cert_hostnames['cn'],
                            "certificate": sni_container.tls_container_id
                        }
                    )
                    # Add subjectAltNames to the mapping table if present
                    try:
                        for alt_name in cert_hostnames['dns_names']:
                            (vserver_config['properties']['ssl']
                                ['server_cert_host_mapping']).append(
                                {
                                    "host": alt_name,
                                    "certificate":
                                        sni_container.tls_container_id
                                }
                            )
                    except TypeError:
                        pass
        # Configure connection limiting if set to 'requests_per_second'...
        if cfg.CONF.lbaas_settings.connection_limit_mode == "requests_per_sec":
            if listener.connection_limit < 1:
                # Delete existing connection limiting settings if not required
                if vtm.rate_class.get(listener.id):
                    vtm.rate_class.delete(listener.id)
                if vtm.rule.get("rate-%s" % listener.id):
                    vtm.rule.delete("rate-%s" % listener.id)
                vserver_config['properties']['basic']['request_rules'] = []
            elif old is None \
            or old.connection_limit != listener.connection_limit:
                # Create connection limiting settings if required
                vtm.rate_class.create(
                    listener.id,
                    max_rate_per_second=listener.connection_limit
                )
                vtm.rule.create(
                    "rate-%s" % listener.id,
                    rule_text='rate.use("%s");' % listener.id
                )
                vserver_config['properties']['basic']['request_rules'] = \
                    ["rate-%s" % listener.id]
        elif old is None or old.connection_limit != listener.connection_limit:
            if listener.connection_limit > 0:
                vserver_config['properties']['basic']['max_concurrent_connections'] = \
                    listener.connection_limit
            else:
                vserver_config['properties']['basic']['max_concurrent_connections'] = 0
        # Create/update virtual server...
        vtm.vserver.create(listener.id, config=vserver_config)
        # Modify Neutron security group to allow access to data port...
        if use_security_group:
            if not old or old.protocol_port != listener.protocol_port:
                protocol = 'udp' if listener.protocol == "UDP" else 'tcp'
                self.openstack_connector.allow_port(
                    listener.loadbalancer, listener.protocol_port, protocol
                )
                if old:
                    self.openstack_connector.block_port(
                        listener.loadbalancer, old.protocol_port, protocol
                    )

    def delete_listener(self, listener, vtm, use_security_group=True):
        vs = vtm.vserver.get(listener.id)
        # Delete Virtual Server
        vs.delete()
        # Delete associated SSL certificates if not still in use
        if listener.protocol == "TERMINATED_HTTPS":
            try:
                tls_containers = [listener.default_tls_container_id] + \
                                 listener.sni_containers
            except TypeError:
                tls_containers = [listener.default_tls_container_id]
            for container in tls_containers:
                cert_in_use = False
                for vserver in vtm.vservers.list():
                    vs = vtm.vserver.get(vserver)
                    if vs.ssl__server_cert_default == container:
                        cert_in_use = True
                    for mapping in vs.ssl__server_cert_host_mapping:
                        if mapping['certificate'] == container:
                            cert_in_use = True
                if cert_in_use is False:
                    vtm.ssl_server_cert.delete(container)
        # Clean up vTM connection-limiting config objects
        if cfg.CONF.lbaas_settings.connection_limit_mode == "requests_per_sec":
            if listener.connection_limit > 0:
                vtm.rules.delete("rate-%s" % listener.id)
                vtm.rate_class.delete(listener.id)
        if use_security_group:
            # Delete security group rule for the listener port/protocol
            protocol = 'udp' if listener.protocol == "UDP" else 'tcp'
            self.openstack_connector.block_port(
                listener.loadbalancer, listener.protocol_port, protocol
            )

#########
# POOLS #
#########

    def create_pool(self, pool):
        self.update_pool(pool, None)

    def update_pool(self, pool, old, vtm, note=None):
        pool_config = {"properties": {
            "basic": {
                "monitors": [],
                "nodes_table": [],
                "note": note or pool.name
            },
            "load_balancing": {
                "algorithm": self.LB_ALGORITHM_MAP[pool.lb_algorithm]
            },
            "connection": {}
        }}
        # Add health monitor to pool if required...
        if pool.healthmonitor_id:
            pool_config['properties']['basic']['monitors'].append(
                pool.healthmonitor_id
            )
        # Add members to the node table...
        for member in pool.members:
            pool_config['properties']['basic']['nodes_table'].append(
                {
                    "node": "%s:%s" % (member.address, member.protocol_port),
                    "weight": member.weight,
                    "state": "active" if member.admin_state_up else "disabled"
                }
            )
        # Configure session persistence if required...
        if pool.lb_algorithm == "SOURCE_IP":
            # vTM has no source IP LB algorithm, so simulate it with
            # round-robin loadbalancing and source IP session persistence
            persistence_config = {"properties": {"basic": {"type": "ip"}}}
            vtm.persistence_class.create(
                pool.id, config=persistence_config
            )
            pool_config['properties']['basic']['persistence_class'] = pool.id
        elif pool.sessionpersistence:
            # Create and apply persistence class if necessary
            persistence_config = {"properties": {
                "basic": {
                    "type": self.PERSISTENCE_MAP[pool.sessionpersistence.type]
                }
            }}
            if pool.sessionpersistence.type == "APP_COOKIE":
                persistence_config['properties']['basic']['cookie'] = \
                    pool.sessionpersistence.cookie_name
            vtm.persistence_class.create(
                pool.id, config=persistence_config
            )
            pool_config['properties']['basic']['persistence_class'] = pool.id
        else:
            pool_config['properties']['basic']['persistence_class'] = ""
        # Create pool...
        vtm.pool.create(pool.id, config=pool_config)
        # Update vserver default pool if it's 'discard'
        vs = vtm.vserver.get(pool.listener.id)
        if vs.pool == 'discard':
            vs.pool = pool.id
            vs.update()
        # Tidy up obsolete persistence class if present
        if old is not None and old.sessionpersistence \
            and not pool.sessionpersistence:
            vtm.persistence_class.delete(pool.id)

    def delete_pool(self, pool, vtm):
        # Reset VS default pool if == this pool
        vs = vtm.vserver.get(pool.listener.id)
        if vs.pool == pool.id:
            vs.pool = 'discard'
            vs.update()
        # Delete the pool itelf
        vtm.pool.delete(pool.id)
        # Delete any associated persistence classes
        if pool.sessionpersistence:
            vtm.persistence_class.delete(pool.id)

###########
# MEMBERS #
###########

    def create_member(self, member):
        LOG.debug(_("\ncreate_member(%s): called" % member.id))
        self.update_member(member, None)
        LOG.debug(_("\ncreate_member(%s): completed!" % member.id))

    def update_member(self, member, old):
        """
        Updates a vTM Pool to include or modify a member.
        vTM does not have a corresponding discrete "member" object.
        """
        LOG.debug(_("\nupdate_member(%s): called" % member.id))
        try:
            self.update_pool(member.pool, None)
            LOG.debug(_("\nupdate_member(%s): completed!" % member.id))
        except Exception as e:
            LOG.error(_("Error in update_member(%s): %e" % (member.id, e)))
            raise

    def delete_member(self, member):
        """
        Updates the vTM Pool to remove the member.
        vTM does not have a corresponding discrete "member" object.
        """
        LOG.debug(_("\ndelete_member(%s): called" % member.id))
        try:
            pool = member.pool
            for mem in pool.members[:]:
                if mem.address == member.address \
                    and mem.protocol_port == member.protocol_port:
                    pool.members.remove(mem)
                    break
            self.update_pool(pool, None)
            LOG.debug(_("\ndelete_member(%s): completed!" % member.id))
        except Exception as e:
            LOG.error(_("Error in delete_member(%s): %e" % (member.id, e)))
            raise

############
# MONITORS #
############

    def create_healthmonitor(self, monitor):
        LOG.debug(_("\ncreate_healthmonitor(%s): called" % monitor.id))
        self.update_healthmonitor(monitor, None)
        LOG.debug(_("\ncreate_healthmonitor(%s): completed!" % monitor.id))

    def update_healthmonitor(self, monitor, old, vtm, note=None):
        monitor_config = {"properties": {
            "basic": {
                "delay": monitor.delay,
                "failures": monitor.max_retries,
                "note": note or monitor.pool.name,
                "timeout": monitor.timeout,
                "type": self.MONITOR_MAP[monitor.type],
                "use_ssl": True if monitor.pool.protocol == "HTTPS" else False
            },
            "http": {
                "path": monitor.url_path,
                "status_regex": self._codes_to_regex(monitor.expected_codes)
            }
        }}
        # Create/update the vTM health monitor object
        vtm.monitor.create(monitor.id, config=monitor_config)
        # Update the vTM pool to use the monitor
        sa_pool = vtm.pool.get(monitor.pool.id)
        sa_pool.monitors = [monitor.id]
        sa_pool.update()

    def delete_healthmonitor(self, monitor, vtm):
        # Delete the vTM health monitor object
        vtm.monitor.delete(monitor.id)
        # Update the vTM pool to remove the monitor
        if monitor.pool:
            sa_pool = vtm.pool.get(monitor.pool.id)
            sa_pool.monitors = []
            sa_pool.update()

#########
# STATS #
#########

    def stats(self, vtm, listen_ip=None):
        if listen_ip:
            stats = vtm.statistics.listen_ips[listen_ip]
            bytes_in = stats.bytes_in
            bytes_out = stats.bytes_out
            active_conns = stats.current_conn
        else:
            stats = vtm.statistics.globals
            bytes_in = stats.total_bytes_in
            bytes_out = stats.total_bytes_out
            active_conns = stats.total_current_conn
        total_conns = stats.total_conn
        return {
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "active_connections": active_conns,
            "total_connections": total_conns
        }

###########
# REFRESH #
###########

    def refresh(self, lb, force):
        self.update_loadbalancer(lb, None)
        for listener in lb.listeners:
            self.update_listener(listener, None)
            # pools = listener.pools  # In prep for L7 routing
            pools = [listener.default_pool]
            for pool in pools:
                self.update_pool(pool, None)
                self.update_healthmonitor(pool.healthmonitor, None)

########
# MISC #
########

    def _codes_to_regex(self, status_codes):
        return "(%s)" % "|".join(
            [
                code.strip() if "-" not in code else "|".join([
                    str(range_code) for range_code in range(
                        int(code.split("-")[0]), int(code.split("-")[1]) + 1
                    )
                ])
                for code in status_codes.split(",")
            ]
        )

    def _get_hostname(self, id):
        return "vtm-%s" % (id)

    def _generate_password(self):
        if cfg.CONF.vtm_settings.admin_password is None:
            chars = ascii_letters + digits
            return "".join(choice(chars) for _ in range(randint(12, 16)))
        return cfg.CONF.vtm_settings.admin_password

    def _upload_certificate(self, vtm, container_id):
        # Get the certificate from Barbican
        cert = certificate_manager.get_cert(
            container_id, service_name="Neutron LBaaS v2 Brocade provider"
        )
        # Check that the private key is not passphrase-protected
        if cert.get_private_key_passphrase():
            raise Exception(_(
                "The vTM LBaaS provider does not support private "
                "keys with a passphrase"
            ))
        # Add server certificate to any intermediates
        try:
            cert_chain = cert.get_certificate() + cert.get_intermediates()
        except TypeError:
            cert_chain = cert.get_certificate()
        # Upload the certificate and key to the vTM
        vtm.ssl_server_cert.create(
            container_id, private=cert.get_private_key(), public=cert_chain
        )
        return cert
