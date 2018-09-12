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

from pulse_neutron_lbaas_tenant_customizations_db import helper \
    as customization_helper
from neutron_lbaas.common.cert_manager import CERT_MANAGER_PLUGIN
from neutron_lbaas.common.exceptions import LbaasException
from neutron_lbaas.common.tls_utils.cert_parser import get_host_names
from openstack_connector import OpenStackInterface
from oslo_config import cfg
from oslo_log import log as logging
from random import choice, randint
from string import ascii_letters, digits
from traceback import format_exc
from vtm import Statistics

LOG = logging.getLogger(__name__)


def logging_wrapper(lbaas_func):
    def log_writer(*args):
        LOG.debug(_(
            "\n{}({}): called".format(
                lbaas_func.__name__, getattr(args[1], "id")
        )))
        try:
            return_value = lbaas_func(*args)
            LOG.debug(_(
                "\n{}({}): completed!".format(
                    lbaas_func.__name__, getattr(args[1], "id")
            )))
            return return_value
        except Exception as e:
            LOG.error(_(
                "\nError in {}({}): {}\n\n{}".format(
                    lbaas_func.__name__,
                    getattr(args[1], "id"),
                    e,
                    format_exc()
            )))
            raise e
    return log_writer


class vTMDeviceDriverCommon(object):
    """
    Common methods/properties
    """

    PROTOCOL_MAP = {
        "HTTP": "http",
        "HTTPS": "https",
        "TCP": "stream",
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

    def __init__(self):
        self.openstack_connector = OpenStackInterface()
        self.certificate_manager = CERT_MANAGER_PLUGIN.CertManager
        # Get connector to tenant customizations database if enabled...
        if cfg.CONF.lbaas_settings.allow_tenant_customizations is True:
            self.customizations_db = customization_helper.\
                PulseLbaasTenantCustomizationsDatabaseHelper(
                    cfg.CONF.lbaas_settings.tenant_customizations_db
                )
        else:
            self.customizations_db = None

#############
# LISTENERS #
#############

    def create_listener(self, listener):
        self.update_listener(listener, None)

    def update_listener(self, listener, old, vtm, listen_on_settings,
                        use_security_group=True, note=None):
        vserver_config = {"properties": {
            "basic": {
                "add_x_forwarded_for": True,
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
            vserver_config['properties']['basic']['ssl_decrypt'] = True
            vserver_config['properties']['ssl'] = self._get_ssl_config(
                vtm, listener
            )
        elif old and old.protocol == "TERMINATED_HTTPS":
            vserver_config['properties']['basic']['ssl_decrypt'] = False
            self._clean_up_certificates(vtm, listener.id)
        # Configure connection limiting...
        if listener.connection_limit > 0:
            vserver_config['properties']['basic']\
                ['max_concurrent_connections'] = listener.connection_limit
        else:
            vserver_config['properties']['basic']\
                ['max_concurrent_connections'] = 0
        # Create/update virtual server...
        vtm.vserver.create(listener.id, config=vserver_config)
        # Modify Neutron security group to allow access to data port...
        if use_security_group:
            identifier = self.openstack_connector.get_identifier(
                listener.loadbalancer
            )
            if not old or old.protocol_port != listener.protocol_port:
                protocol = 'udp' if listener.protocol == "UDP" else 'tcp'
                self.openstack_connector.allow_port(
                    listener.loadbalancer, listener.protocol_port, identifier,
                    protocol
                )
                if old:
                    self.openstack_connector.block_port(
                        listener.loadbalancer, old.protocol_port, identifier,
                        protocol
                    )

    def delete_listener(self, listener, vtm, use_security_group=True):
        # Delete associated SSL certificates
        if listener.protocol == "TERMINATED_HTTPS":
            self._clean_up_certificates(vtm, listener.id)
        if use_security_group:
            # Delete security group rule for the listener port/protocol
            protocol = 'udp' if listener.protocol == "UDP" else 'tcp'
            identifier = self.openstack_connector.get_identifier(
                listener.loadbalancer
            )
            self.openstack_connector.block_port(
                listener.loadbalancer, listener.protocol_port, identifier,
                protocol
            )
        # Delete Virtual Server
        vs = vtm.vserver.get(listener.id)
        vs.delete()

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
            }
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
                    "node": "{}:{}".format(
                        member.address, member.protocol_port
                    ),
                    "weight": member.weight,
                    "state": "active" if member.admin_state_up else "disabled"
                }
            )
        # Configure session persistence if required...
        if pool.sessionpersistence:
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
        elif pool.lb_algorithm == "SOURCE_IP":
            # vTM has no source IP LB algorithm, so simulate it with
            # round-robin loadbalancing and source IP session persistence
            persistence_config = {"properties": {"basic": {"type": "ip"}}}
            vtm.persistence_class.create(
                pool.id, config=persistence_config
            )
            pool_config['properties']['basic']['persistence_class'] = pool.id
        else:
            pool_config['properties']['basic']['persistence_class'] = ""
        # Create pool...
        vtm.pool.create(pool.id, config=pool_config)
        # If pool has a listener, update vserver default pool if it's 'discard'
        if pool.listener is not None:
            vs = vtm.vserver.get(pool.listener.id)
            if vs.pool == 'discard':
                vs.pool = pool.id
                vs.update()
        # Tidy up obsolete persistence class if present
        if((old is not None
            and old.sessionpersistence 
            and not pool.sessionpersistence)
        or (old is not None
            and old.lb_algorithm == "SOURCE_IP"
            and pool.lb_algorithm != "SOURCE_IP")
        ):
            vtm.persistence_class.delete(pool.id)

    def delete_pool(self, pool, vtm):
        # If pool has a listener, reset vserver default pool to 'discard'
        if pool.listener is not None:
            vs = vtm.vserver.get(pool.listener.id)
            if vs.pool == pool.id:
                vs.pool = 'discard'
                vs.update()
        # Delete the pool itelf
        vtm.pool.delete(pool.id)
        # Delete any associated persistence classes
        if pool.sessionpersistence or pool.lb_algorithm == "SOURCE_IP":
            vtm.persistence_class.delete(pool.id)

###########
# MEMBERS #
###########

    @logging_wrapper
    def create_member(self, member):
        self.update_member(member, None)

    @logging_wrapper
    def update_member(self, member, old):
        """
        Updates a vTM Pool to include or modify a member.
        vTM does not have a corresponding discrete "member" object.
        """
        self.update_pool(member.pool, None)

    @logging_wrapper
    def delete_member(self, member):
        """
        Updates the vTM Pool to remove the member.
        vTM does not have a corresponding discrete "member" object.
        """
        pool = member.pool
        for mem in pool.members[:]:
            if mem.address == member.address \
                and mem.protocol_port == member.protocol_port:
                pool.members.remove(mem)
                break
        self.update_pool(member.pool, None)

    def get_member_health(self, member, vtm):
        """
        Return the health of the specified node.
        """
        target_node = "{}:{}".format(member.address, member.protocol_port)
        state = vtm.get_state()
        for node in state['failed_nodes']:
            if target_node == node['node']:
                if member.pool.id in node['pools']:
                    return "INACTIVE"
        return "ACTIVE"

############
# MONITORS #
############

    @logging_wrapper
    def create_healthmonitor(self, monitor):
        self.update_healthmonitor(monitor, None)

    def update_healthmonitor(self, monitor, old, vtm, note=None):
        monitor_config = {"properties": {
            "basic": {
                "delay": monitor.delay,
                "failures": monitor.max_retries,
                "note": note or monitor.pool.name,
                "timeout": monitor.timeout,
                "type": self.MONITOR_MAP[monitor.type],
                "use_ssl": True if monitor.type == "HTTPS" else False
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


###############
# L7 POLICIES #
###############

    @logging_wrapper
    def create_l7_policy(self, policy):
        # No point creating policy until there are rules to go in it!
        pass

    def update_l7_policy(self, policy, old, vtm):
        if not policy.rules:
            self.delete_l7_policy(policy)
            return
        # Create the TrafficScript(tm) rule
        ts_rule_name = "l7policy-{}".format(policy.id)
        trafficscript = self._build_trafficscript(policy)
        vtm.rule.create(ts_rule_name, rule_text=trafficscript)
        # Make sure the rules are in the correct order
        vserver = vtm.vserver.get(policy.listener_id)
        policies = vserver.request_rules
        try:
            policies.remove(ts_rule_name)
        except ValueError:
            pass
        position = policy.position
        if position is None:
            # No position specified, so just append the rule
            policies.append(ts_rule_name)
        else:
            try:
                # Ensure l7 rules remain below rate-shaping rules
                if vserver.request_rules[0].startswith("rate-"):
                    position += 1
            except IndexError:
                pass
            if position >= len(policies):
                policies.append(ts_rule_name)
            else:
                policies.insert(position, ts_rule_name)
        # Apply ordered rules to vserver
        vserver.request_rules = policies
        vserver.update()

    def delete_l7_policy(self, policy, vtm):
        ts_rule_name = "l7policy-{}".format(policy.id)
        vserver = vtm.vserver.get(policy.listener_id)
        try:
            vserver.request_rules.remove(ts_rule_name)
            vserver.update()
            vtm.rule.delete(ts_rule_name)
        except ValueError:
            # May have already been deleted if rules were deleted individually
            pass

############
# L7 RULES #
############

    @logging_wrapper
    def create_l7_rule(self, rule):
        self.update_l7_rule(rule, None)

    @logging_wrapper
    def update_l7_rule(self, rule, old):
        self.update_l7_policy(rule.policy, None)

    @logging_wrapper
    def delete_l7_rule(self, rule_to_delete):
        policy = rule_to_delete.policy
        policy.rules = [
            rule for rule in policy.rules
            if rule.id != rule_to_delete.id
        ]
        self.update_l7_policy(policy, None)

#########
# STATS #
#########

    def stats(self, vtm, listen_ip=None):
        try:
            if listen_ip:
                stats = vtm.statistics.listen_ips[listen_ip]
                return {
                    "bytes_in": stats.bytes_in,
                    "bytes_out": stats.bytes_out,
                    "active_connections": stats.current_conn,
                    "total_connections": stats.total_requests
                }
            else:
                stats = vtm.statistics.globals
                return {
                    "bytes_in": stats.total_bytes_in,
                    "bytes_out": stats.total_bytes_out,
                    "active_connections": stats.total_current_conn,
                    "total_connections": stats.total_conn
                }
        except (Statistics.Section.NoDataAvailableError,
                Statistics.Section.NoCountersReturnedError):
            return {
                "bytes_in": -1,
                "bytes_out": -1,
                "active_connections": -1,
                "total_connections": -1
            }

###########
# REFRESH #
###########

    @logging_wrapper
    def refresh(self, lb, force):
        self.update_loadbalancer(lb, None)
        for listener in lb.listeners:
            self.update_listener(listener, None)
            pools = listener.pools
            for pool in pools:
                self.update_pool(pool, None)
                self.update_healthmonitor(pool.healthmonitor, None)

########
# MISC #
########

    def _get_setting(self, tenant_id, section, param):
        setting = None
        if self.customizations_db:
            setting = self.customizations_db.get_customization(
                tenant_id, section, param
            )
        if setting is None:
            global_section = getattr(cfg.CONF, section)
            setting = getattr(global_section, param)
        return setting

    def _get_custom_settings(self, tenant_id):
        if self.customizations_db:
            return self.customizations_db.get_all_tenant_customizations(
                tenant_id
            )
        return None

    def _codes_to_regex(self, status_codes):
        return "({})".format("|".join(
            [
                code.strip() if "-" not in code else "|".join([
                    str(range_code) for range_code in range(
                        int(code.split("-")[0]), int(code.split("-")[1]) + 1
                    )
                ])
                for code in status_codes.split(",")
            ]
        ))

    def _build_trafficscript(self, policy):
        key_map = {
            "HOST_NAME": "http.getHostHeader()",
            "PATH": "http.getPath()",
            "HEADER": "http.getHeader('{}')",
            "COOKIE": "http.getCookie('{}')",
            "FILE_TYPE": "string.split(http.getPath(), '.')[-1]"
        }
        comp_map = {
            "REGEX": "string.regexMatch({}, '{}')",
            "STARTS_WITH": "string.startsWith({}, '{}')",
            "ENDS_WITH": "string.endsWith({}, '{}')",
            "CONTAINS": "string.contains({}, '{}')",
            "EQUAL_TO": "({} == '{}')"
        }
        # Build a list of TrafficScript conditions from the rules
        condition_list = []
        for rule in policy.rules:
            rule_key = key_map[rule.type]
            if "'{}'" in rule_key:
                rule_key = rule_key.format(rule.key)
            condition = comp_map[rule.compare_type].format(rule_key, rule.value)
            if rule.invert:
                condition = "! {}".format(condition)
            condition_list.append(condition)
        # Select the TrafficScript action to take
        action = ""
        if policy.action == "REJECT":
            action = "connection.drop();"
        elif policy.action == "REDIRECT_TO_POOL":
            action = "pool.use('{}');".format(policy.redirect_pool_id)
        elif policy.action == "REDIRECT_TO_URL":
            action = "http.redirect('{}');".format(policy.redirect_url)
        # Generate TrafficScript
        trafficscript = "if({})\n{{\n\t{}\n}}".format(
            "\n|| ".join(condition_list),
            action
        )
        return trafficscript

    def _generate_password(self):
        if cfg.CONF.vtm_settings.password is None:
            chars = ascii_letters + digits
            return "".join(choice(chars) for _ in range(randint(12, 16)))
        return cfg.CONF.vtm_settings.password

    def _get_container_id(self, container_ref):
        return container_ref[container_ref.rfind("/")+1:]

    def _get_ssl_config(self, vtm, listener):
        container_id = self._get_container_id(
            listener.default_tls_container_id
        )
        # Upload default certificate
        default_cert_name, cert = self._upload_certificate(
            vtm, listener.id, listener.default_tls_container_id
        )
        # Set default certificate
        ssl_settings = {
            "server_cert_default": default_cert_name,
            "server_cert_host_mapping": []
        }
        # Configure SNI certificates
        if listener.sni_containers:
            for sni_container in listener.sni_containers:
                container_id = self._get_container_id(
                    sni_container.tls_container_id
                 )
                # Get cert from Barbican and upload to vTM
                cert_name, cert = self._upload_certificate(
                    vtm, listener.id, sni_container.tls_container_id
                )
                # Get CN and subjectAltNames from certificate
                cert_hostnames = get_host_names(cert.get_certificate())
                # Add the CN and the certificate to the virtual server
                # SNI certificate mapping table
                ssl_settings['server_cert_host_mapping'].append(
                    {
                        "host": cert_hostnames['cn'],
                        "certificate": cert_name
                    }
                )
                # Add subjectAltNames to the mapping table if present
                try:
                    for alt_name in cert_hostnames['dns_names']:
                        ssl_settings['server_cert_host_mapping'].append(
                            {
                                "host": alt_name,
                                "certificate": cert_name
                            }
                        )
                except TypeError:
                    pass
        return ssl_settings

    def _upload_certificate(self, vtm, listener_id, container_id):
        # Get the certificate from Barbican
        cert = self.certificate_manager.get_cert(
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
        cert_name = "{}-{}".format(
            listener_id, self._get_container_id(container_id)
        )
        vtm.ssl_server_cert.create(
            cert_name, private=cert.get_private_key(), public=cert_chain
        )
        return cert_name, cert

    def _clean_up_certificates(self, vtm, listener_id):
        vs = vtm.vserver.get(listener_id)
        # Delete default certificate
        vtm.ssl_server_cert.delete(vs.ssl__server_cert_default)
        # Delete SNI certificates
        for sni_cert in vs.ssl__server_cert_host_mapping:
            vtm.ssl_server_cert.delete(sni_cert['certificate'])
