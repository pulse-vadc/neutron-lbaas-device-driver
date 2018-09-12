#!/usr/bin/env python

from ..environment import env_data
import pytest
from ..lib.vtm_object_templates import virtual_server


@pytest.fixture()
def create_tcp_listener(neutron, loadbalancer):
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyTcpListener1",
            "protocol_port": 22,
            "protocol": "TCP",
            "loadbalancer_id": loadbalancer['id']
        }}
    )
    yield {
        "listener_id": listener['listener']['id'],
        "loadbalancer_id": loadbalancer['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_create_tcp_listener(assert_functions, create_tcp_listener):
    context = create_tcp_listener
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    port=22,
                    protocol="stream"
                )
            ]
        }
    )
    assert_functions.assert_security_group_rule_exists(
        "lbaas-{}".format(context['loadbalancer_id']), 22
    )


@pytest.fixture(scope="module")
def create_http_listener_basic(neutron, loadbalancer):
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyHttpListener1",
            "protocol_port": 80,
            "protocol": "HTTP",
            "loadbalancer_id": loadbalancer['id']
        }}
    )
    yield {
        "listener_id": listener['listener']['id'],
        "loadbalancer_id": loadbalancer['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_create_http_listener_basic(assert_functions, create_http_listener_basic):
    context = create_http_listener_basic
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']]
                )
            ]
        }
    )
    assert_functions.assert_security_group_rule_exists(
        "lbaas-{}".format(context['loadbalancer_id']), 80
    )


@pytest.fixture()
def create_http_listener_with_connection_limiting(neutron, loadbalancer):
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyHttpListener2",
            "protocol_port": 8080,
            "protocol": "HTTP",
            "connection_limit": 10,
            "loadbalancer_id": loadbalancer['id']
        }}
    )
    yield {
        "listener_id": listener['listener']['id'],
        "loadbalancer_id": loadbalancer['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_create_http_listener_with_connection_limiting(
    assert_functions,
    create_http_listener_with_connection_limiting
):
    context = create_http_listener_with_connection_limiting
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    max_concurrent_connections=10,
                    port=8080
                )
            ]
        }
    )


@pytest.fixture()
def update_http_listener_set_conn_limit_on(neutron, loadbalancer):
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyHttpListener1",
            "protocol_port": 8080,
            "protocol": "HTTP",
            "loadbalancer_id": loadbalancer['id']
        }}
    )
    neutron.update_listener(
        listener['listener']['id'],
        {"listener": {
            "connection_limit": 10
        }}
    )
    yield {
        "listener_id": listener['listener']['id'],
        "loadbalancer_id": loadbalancer['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_update_listener_turn_conn_limit_on(
    assert_functions,
    update_http_listener_set_conn_limit_on
):
    context = update_http_listener_set_conn_limit_on
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    max_concurrent_connections=10,
                    port=8080
                )
            ]
        }
    )


@pytest.fixture()
def update_http_listener_set_conn_limit_off(neutron, loadbalancer):
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyHttpListener1",
            "protocol_port": 8080,
            "protocol": "HTTP",
            "connection_limit": 10,
            "loadbalancer_id": loadbalancer['id']
        }}
    )
    neutron.update_listener(
        listener['listener']['id'],
        {"listener": {
            "connection_limit": -1
        }}
    )
    yield {
        "listener_id": listener['listener']['id'],
        "loadbalancer_id": loadbalancer['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_update_listener_turn_conn_limit_off(
    assert_functions,
    update_http_listener_set_conn_limit_off
):
    context = update_http_listener_set_conn_limit_off
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    port=8080
                )
            ]
        }
    )


@pytest.fixture()
def create_https_listener(neutron, loadbalancer):
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyHttpsListener1",
            "protocol_port": 443,
            "protocol": "HTTPS",
            "loadbalancer_id": loadbalancer['id']
        }}
    )
    yield {
        "listener_id": listener['listener']['id'],
        "loadbalancer_id": loadbalancer['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_create_https_listener(assert_functions, create_https_listener):
    context = create_https_listener
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    port=443,
                    protocol="https"
                )
            ]
        }
    )


@pytest.fixture()
def create_tls_offload_listener_no_sni(neutron, barbican, loadbalancer):
    keypair = barbican.generate_keypair("MAIN", "www.main.com")
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyTlsListenerNoSni",
            "protocol_port": 443,
            "protocol": "TERMINATED_HTTPS",
            "loadbalancer_id": loadbalancer['id'],
            "default_tls_container_id": "{}/containers/{}".format(
                env_data['barbican_url'], keypair
            )
        }}
    )
    yield {
        "loadbalancer_id": loadbalancer['id'],
        "container_id": keypair,
        "listener_id": listener['listener']['id']
    }
    neutron.delete_listener(listener['listener']['id'])


def test_create_tls_offload_listener_no_sni(
    assert_functions,
    create_tls_offload_listener_no_sni
):
    context = create_tls_offload_listener_no_sni
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    port=443,
                    ssl_decrypt=True,
                    server_cert_default="{}-{}".format(
                        context['listener_id'], context['container_id']
                    )
                )
            ]
        }
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['container_id']
    )


@pytest.fixture()
def create_tls_offload_listener_with_sni(neutron, barbican, loadbalancer):
    main_keypair = barbican.generate_keypair("MAIN", "www.main.com")
    sni_keypair_1 = barbican.generate_keypair("SNI1", "www.sni1.com")
    sni_keypair_2 = barbican.generate_keypair("SNI2", "www.sni2.com")
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyTlsListenerWithSni",
            "protocol_port": 443,
            "protocol": "TERMINATED_HTTPS",
            "loadbalancer_id": loadbalancer['id'],
            "default_tls_container_id": "{}/containers/{}".format(
                env_data['barbican_url'], main_keypair
            ),
            "sni_container_ids": [
                "{}/containers/{}".format(
                    env_data['barbican_url'], sni_keypair_1
                ),
                "{}/containers/{}".format(
                    env_data['barbican_url'], sni_keypair_2
                )
            ]
        }}
    )
    yield {
        "loadbalancer_id": loadbalancer['id'],
        "main_container_id": main_keypair,
        "sni_1_container_id": sni_keypair_1,
        "sni_2_container_id": sni_keypair_2,
        "listener_id": listener['listener']['id']
    }
    neutron.delete_listener(listener['listener']['id'])
    barbican.delete_keypair(main_keypair)
    barbican.delete_keypair(sni_keypair_1)
    barbican.delete_keypair(sni_keypair_2)


def test_create_tls_offload_listener_with_sni(
    assert_functions,
    create_tls_offload_listener_with_sni
):
    context = create_tls_offload_listener_with_sni
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    port=443,
                    ssl_decrypt=True,
                    server_cert_default="{}-{}".format(
                        context['listener_id'], context['main_container_id']
                    ),
                    server_cert_host_mapping=[
                        {
                            "alt_certificates": [],
                            "host": "www.sni1.com",
                            "certificate": "{}-{}".format(
                                context['listener_id'],
                                context['sni_1_container_id']
                            )
                        },
                        {
                            "alt_certificates": [],
                            "host": "www.sni2.com",
                            "certificate": "{}-{}".format(
                                context['listener_id'],
                                context['sni_2_container_id']
                            )
                        }
                    ]

                )
            ]
        }
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['main_container_id']
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['sni_1_container_id']
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['sni_2_container_id']
    )

"""
@pytest.fixture()
def update_tls_listener_with_sni_change_certs(neutron, barbican, loadbalancer):
    main_keypair = barbican.generate_keypair("MAIN", "www.main.com")
    replacement_keypair = barbican.generate_keypair("NEW_MAIN", "www.new_main.com")
    sni_keypair_1 = barbican.generate_keypair("SNI1", "www.sni1.com")
    sni_keypair_2 = barbican.generate_keypair("SNI2", "www.sni2.com")
    sni_keypair_3 = barbican.generate_keypair("SNI3", "www.sni3.com")
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyTlsListenerWithSniChangeCert",
            "protocol_port": 666,
            "protocol": "TERMINATED_HTTPS",
            "loadbalancer_id": loadbalancer['id'],
            "default_tls_container_id": "{}/containers/{}".format(env_data['barbican_url'], main_keypair),
            "sni_container_ids": [
                "{}/containers/{}".format(env_data['barbican_url'], sni_keypair_1),
                "{}/containers/{}".format(env_data['barbican_url'], sni_keypair_2)
            ]
        }}
    )
    neutron.update_listener(
        listener['listener']['id'],
        {"listener": {
            "default_tls_container_id": "{}/containers/{}".format(env_data['barbican_url'], replacement_keypair),
            "sni_container_ids": [
                "{}/containers/{}".format(env_data['barbican_url'], sni_keypair_1),
                "{}/containers/{}".format(env_data['barbican_url'], sni_keypair_3)
            ]
        }}
    )
    yield {
        "loadbalancer_id": loadbalancer['id'],
        "main_container_id": main_keypair,
        "replacement_container_id": replacement_keypair,
        "sni_1_container_id": sni_keypair_1,
        "sni_2_container_id": sni_keypair_2,
        "sni_3_container_id": sni_keypair_3,
        "listener_id": listener['listener']['id']
    }
    neutron.delete_listener(listener['listener']['id'])
    barbican.delete_keypair(main_keypair)
    barbican.delete_keypair(replacement_keypair)
    barbican.delete_keypair(sni_keypair_1)
    barbican.delete_keypair(sni_keypair_2)
    barbican.delete_keypair(sni_keypair_3)


def test_update_tls_listener_with_sni_change_certs(
    assert_functions,
    update_tls_listener_with_sni_change_certs
):
    context = update_tls_listener_with_sni_change_certs
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    context['listener_id'],
                    listen_on_traffic_ips=[context['loadbalancer_id']],
                    port=666,
                    ssl_decrypt=True,
                    server_cert_default="{}-{}".format(
                        context['listener_id'], context['replacement_container_id']
                    ),
                    server_cert_host_mapping=[
                        {
                            "alt_certificates": [],
                            "host": "www.sni1.com",
                            "certificate": "{}-{}".format(
                                context['listener_id'],
                                context['sni_1_container_id']
                            )
                        },
                        {
                            "alt_certificates": [],
                            "host": "www.sni3.com",
                            "certificate": "{}-{}".format(
                                context['listener_id'],
                                context['sni_3_container_id']
                            )
                        }
                    ]

                )
            ]
        }
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['replacement_container_id']
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['sni_1_container_id']
    )
    assert_functions.assert_certificates_match(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        context['listener_id'],
        context['sni_3_container_id']
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        "ssl/server_keys",
        "{}-{}".format(context['listener_id'], context['main_container_id'])
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        "ssl/server_keys",
        "{}-{}".format(context['listener_id'], context['sni_2_container_id'])
    )
"""

@pytest.fixture()
def delete_listener(neutron, barbican, loadbalancer):
    main_keypair = barbican.generate_keypair("MAIN", "www.main.com")
    sni_keypair_1 = barbican.generate_keypair("SNI1", "www.sni1.com")
    listener = neutron.create_listener(
        {"listener": {
            "name": "MyTlsListenerTBD",
            "protocol_port": 443,
            "protocol": "TERMINATED_HTTPS",
            "loadbalancer_id": loadbalancer['id'],
            "default_tls_container_id": "{}/containers/{}".format(
                env_data['barbican_url'], main_keypair
            ),
            "sni_container_ids": [
                "{}/containers/{}".format(
                    env_data['barbican_url'], sni_keypair_1
                )
            ]
        }}
    )
    neutron.delete_listener(listener['listener']['id'])
    yield {
        "loadbalancer_id": loadbalancer['id'],
        "main_container_id": main_keypair,
        "sni_1_container_id": sni_keypair_1,
        "listener_id": listener['listener']['id']
    }
    barbican.delete_keypair(main_keypair)
    barbican.delete_keypair(sni_keypair_1)


def test_delete_listener(assert_functions, delete_listener):
    context = delete_listener
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        "virtual_servers",
        context['listener_id']
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        "ssl/server_keys",
        "{}-{}".format(context['listener_id'], context['main_container_id'])
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(context['loadbalancer_id']),
        "ssl/server_keys",
        "{}-{}".format(context['listener_id'], context['sni_1_container_id'])
    )
    assert_functions.assert_security_group_rule_not_exists(
        "lbaas-{}".format(context['loadbalancer_id']), 443
    )
