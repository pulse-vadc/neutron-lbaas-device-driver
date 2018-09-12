#!/usr/bin/env python

from ..environment import env_data
import pytest
from test_listeners import create_http_listener_basic
from ..lib.vtm_object_templates import persistence, pool, virtual_server


@pytest.fixture()
def create_round_robin_pool(neutron, create_http_listener_basic):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool1",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "ROUND_ROBIN"
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_create_round_robin_pool(assert_functions, create_round_robin_pool):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_round_robin_pool['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    create_round_robin_pool['listener_id'],
                    pool=create_round_robin_pool['pool_id'],
                    listen_on_traffic_ips=[create_round_robin_pool['loadbalancer_id']]
                )
            ],
            "pools": [
                pool(
                    create_round_robin_pool['pool_id'],
                    algorithm="weighted_round_robin"
                )
            ]
        }
    )


@pytest.fixture()
def create_least_connections_pool(neutron, create_http_listener_basic):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool2",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "LEAST_CONNECTIONS"
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_create_least_connections_pool(
    assert_functions,
    create_least_connections_pool
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_least_connections_pool['loadbalancer_id']),
        {
            "virtual_servers": [
                virtual_server(
                    create_least_connections_pool['listener_id'],
                    pool=create_least_connections_pool['pool_id'],
                    listen_on_traffic_ips=[create_least_connections_pool['loadbalancer_id']]
                )
            ],
            "pools": [
                pool(
                    create_least_connections_pool['pool_id'],
                    algorithm="weighted_least_connections"
                )
            ]
        }
    )


@pytest.fixture()
def create_source_ip_pool(neutron, create_http_listener_basic):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool3",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "SOURCE_IP"
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_create_source_ip_pool(assert_functions, create_source_ip_pool):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_source_ip_pool['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_source_ip_pool['pool_id'],
                    algorithm="weighted_round_robin",
                    persistence_class=create_source_ip_pool['pool_id']
                )
            ],
            "persistence": [
                persistence(
                    create_source_ip_pool['pool_id'],
                    type="ip"
                )
            ]
        }
    )


@pytest.fixture()
def update_source_ip_pool_change_algorithm(neutron, create_source_ip_pool):
    pool = neutron.update_lbaas_pool(
        create_source_ip_pool['pool_id'],
        {"pool": {
            "lb_algorithm": "ROUND_ROBIN"
        }}
    )
    yield {
        "pool_id": create_source_ip_pool['pool_id'],
        "loadbalancer_id": create_source_ip_pool['loadbalancer_id'],
    }


def test_update_source_ip_pool_change_algorithm(
    assert_functions,
    update_source_ip_pool_change_algorithm
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(update_source_ip_pool_change_algorithm['loadbalancer_id']),
        {
            "pools": [
                pool(
                    update_source_ip_pool_change_algorithm['pool_id'],
                    algorithm="weighted_round_robin",
                    persistence_class=""
                )
            ]
        }
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(update_source_ip_pool_change_algorithm['loadbalancer_id']),
        "persistence",
        update_source_ip_pool_change_algorithm['pool_id']
    )


@pytest.fixture()
def create_pool_with_ip_persistence(neutron, create_http_listener_basic):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool4",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "ROUND_ROBIN",
            "session_persistence": {
                "type": "SOURCE_IP"
            }
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_create_pool_with_ip_persistence(
    assert_functions,
    create_pool_with_ip_persistence
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_pool_with_ip_persistence['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_pool_with_ip_persistence['pool_id'],
                    algorithm="weighted_round_robin",
                    persistence_class=create_pool_with_ip_persistence['pool_id']
                )
            ],
            "persistence": [
                persistence(
                    create_pool_with_ip_persistence['pool_id'],
                    type="ip"
                )
            ]
        }
    )


@pytest.fixture()
def create_pool_with_http_cookie_persistence(
    neutron,
    create_http_listener_basic
):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool5",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "ROUND_ROBIN",
            "session_persistence": {
                "type": "HTTP_COOKIE"
            }
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_create_pool_with_http_cookie_persistence(
    assert_functions,
    create_pool_with_http_cookie_persistence
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_pool_with_http_cookie_persistence['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_pool_with_http_cookie_persistence['pool_id'],
                    algorithm="weighted_round_robin",
                    persistence_class=create_pool_with_http_cookie_persistence['pool_id']
                )
            ],
            "persistence": [
                persistence(
                    create_pool_with_http_cookie_persistence['pool_id'],
                    type="transparent"
                )
            ]
        }
    )


@pytest.fixture()
def create_pool_with_app_cookie_persistence(
    neutron,
    create_http_listener_basic
):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool6",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "ROUND_ROBIN",
            "session_persistence": {
                "type": "APP_COOKIE",
                "cookie_name": "MyMagicCookie"
            }
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_create_pool_with_app_cookie_persistence(
    assert_functions,
    create_pool_with_app_cookie_persistence
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(
            create_pool_with_app_cookie_persistence['loadbalancer_id']
        ),
        {
            "pools": [
                pool(
                    create_pool_with_app_cookie_persistence['pool_id'],
                    algorithm="weighted_round_robin",
                    persistence_class=create_pool_with_app_cookie_persistence['pool_id']
                )
            ],
            "persistence": [
                persistence(
                    create_pool_with_app_cookie_persistence['pool_id'],
                    type="cookie",
                    cookie="MyMagicCookie"
                )
            ]
        }
    )


@pytest.fixture()
def update_pool_remove_persistence(neutron, create_http_listener_basic):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool7",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "ROUND_ROBIN",
            "session_persistence": {
                "type": "SOURCE_IP"
            }
        }}
    )
    neutron.update_lbaas_pool(
        pool['pool']['id'],
        {"pool": {
            "session_persistence": {}
        }}
    )
    yield {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }
    neutron.delete_lbaas_pool(pool['pool']['id'])


def test_update_pool_remove_persistence(
    assert_functions,
    update_pool_remove_persistence
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(update_pool_remove_persistence['loadbalancer_id']),
        {
            "pools": [
                pool(
                    update_pool_remove_persistence['pool_id'],
                    algorithm="weighted_round_robin",
                    persistence_class=""
                )
            ]
        }
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(update_pool_remove_persistence['loadbalancer_id']),
        "persistence",
        update_pool_remove_persistence['pool_id']
    )


@pytest.fixture()
def delete_pool(neutron, create_http_listener_basic):
    pool = neutron.create_lbaas_pool(
        {"pool": {
            "name": "MyPool8",
            "listener_id": create_http_listener_basic['listener_id'],
            "protocol": "HTTP",
            "lb_algorithm": "SOURCE_IP"
        }}
    )
    neutron.delete_lbaas_pool(pool['pool']['id'])
    return {
        "pool_id": pool['pool']['id'],
        "listener_id": create_http_listener_basic['listener_id'],
        "loadbalancer_id": create_http_listener_basic['loadbalancer_id'],
    }


def test_delete_pool(assert_functions, delete_pool):
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(delete_pool['loadbalancer_id']),
        "pools",
        delete_pool['pool_id']
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(delete_pool['loadbalancer_id']),
        "persistence",
        delete_pool['pool_id']
    )

