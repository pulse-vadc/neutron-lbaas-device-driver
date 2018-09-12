#!/usr/bin/env python

from ..environment import env_data
import pytest
from test_listeners import create_http_listener_basic
from test_members import create_round_robin_pool
from ..lib.vtm_object_templates import pool, monitor


@pytest.fixture()
def create_ping_healthmonitor(neutron, create_round_robin_pool):
    monitor = neutron.create_lbaas_healthmonitor(
        {"healthmonitor": {
            "pool_id": create_round_robin_pool['pool_id'],
            "type": "PING",
            "max_retries": 6,
            "delay": 6,
            "timeout": 6
        }}
    )
    yield {
        "monitor_id": monitor['healthmonitor']['id'],
        "pool_id": create_round_robin_pool['pool_id'],
        "loadbalancer_id": create_round_robin_pool['loadbalancer_id'],
    }
    neutron.delete_lbaas_healthmonitor(monitor['healthmonitor']['id'])


def test_create_ping_healthmonitor(assert_functions, create_ping_healthmonitor):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_ping_healthmonitor['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_ping_healthmonitor['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[],
                    monitors=[create_ping_healthmonitor['monitor_id']]
                )
            ],
            "monitors": [
                monitor(
                    create_ping_healthmonitor['monitor_id'],
                    type="ping",
                    failures=6,
                    delay=6,
                    timeout=6
                )
            ]
        }
    )


@pytest.fixture()
def create_tcp_healthmonitor(neutron, create_round_robin_pool):
    monitor = neutron.create_lbaas_healthmonitor(
        {"healthmonitor": {
            "pool_id": create_round_robin_pool['pool_id'],
            "type": "TCP",
            "max_retries": 7,
            "delay": 12,
            "timeout": 67
        }}
    )
    yield {
        "monitor_id": monitor['healthmonitor']['id'],
        "pool_id": create_round_robin_pool['pool_id'],
        "loadbalancer_id": create_round_robin_pool['loadbalancer_id'],
    }
    neutron.delete_lbaas_healthmonitor(monitor['healthmonitor']['id'])


def test_create_tcp_healthmonitor(assert_functions, create_tcp_healthmonitor):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_tcp_healthmonitor['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_tcp_healthmonitor['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[],
                    monitors=[create_tcp_healthmonitor['monitor_id']]
                )
            ],
            "monitors": [
                monitor(
                    create_tcp_healthmonitor['monitor_id'],
                    type="connect",
                    failures=7,
                    delay=12,
                    timeout=67
                )
            ]
        }
    )


@pytest.fixture()
def create_http_healthmonitor(neutron, create_round_robin_pool):
    monitor = neutron.create_lbaas_healthmonitor(
        {"healthmonitor": {
            "pool_id": create_round_robin_pool['pool_id'],
            "type": "HTTP",
            "max_retries": 2,
            "delay": 3,
            "timeout": 4,
            "url_path": "/testpath",
            "expected_codes": "200,201,204"
        }}
    )
    yield {
        "monitor_id": monitor['healthmonitor']['id'],
        "pool_id": create_round_robin_pool['pool_id'],
        "loadbalancer_id": create_round_robin_pool['loadbalancer_id'],
    }
    neutron.delete_lbaas_healthmonitor(monitor['healthmonitor']['id'])


def test_create_http_healthmonitor(assert_functions, create_http_healthmonitor):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_http_healthmonitor['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_http_healthmonitor['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[],
                    monitors=[create_http_healthmonitor['monitor_id']]
                )
            ],
            "monitors": [
                monitor(
                    create_http_healthmonitor['monitor_id'],
                    type="http",
                    failures=2,
                    delay=3,
                    timeout=4,
                    path="/testpath",
                    status_regex="(200|201|204)"
                )
            ]
        }
    )


@pytest.fixture()
def create_https_healthmonitor(neutron, create_round_robin_pool):
    monitor = neutron.create_lbaas_healthmonitor(
        {"healthmonitor": {
            "pool_id": create_round_robin_pool['pool_id'],
            "type": "HTTPS",
            "max_retries": 2,
            "delay": 3,
            "timeout": 4,
            "url_path": "/testpath",
            "expected_codes": "200,201,204"
        }}
    )
    yield {
        "monitor_id": monitor['healthmonitor']['id'],
        "pool_id": create_round_robin_pool['pool_id'],
        "loadbalancer_id": create_round_robin_pool['loadbalancer_id'],
    }
    neutron.delete_lbaas_healthmonitor(monitor['healthmonitor']['id'])


def test_create_https_healthmonitor(assert_functions, create_https_healthmonitor):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_https_healthmonitor['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_https_healthmonitor['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[],
                    monitors=[create_https_healthmonitor['monitor_id']]
                )
            ],
            "monitors": [
                monitor(
                    create_https_healthmonitor['monitor_id'],
                    type="http",
                    failures=2,
                    delay=3,
                    timeout=4,
                    path="/testpath",
                    status_regex="(200|201|204)",
                    use_ssl=True
                )
            ]
        }
    )


@pytest.fixture()
def delete_healthmonitor(neutron, create_round_robin_pool):
    monitor = neutron.create_lbaas_healthmonitor(
        {"healthmonitor": {
            "pool_id": create_round_robin_pool['pool_id'],
            "type": "HTTPS",
            "max_retries": 2,
            "delay": 3,
            "timeout": 4,
            "url_path": "/testpath",
            "expected_codes": "200,201,204"
        }}
    )
    neutron.delete_lbaas_healthmonitor(monitor['healthmonitor']['id'])
    yield {
        "monitor_id": monitor['healthmonitor']['id'],
        "pool_id": create_round_robin_pool['pool_id'],
        "loadbalancer_id": create_round_robin_pool['loadbalancer_id'],
    }


def test_delete_healthmonitor(assert_functions, delete_healthmonitor):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(delete_healthmonitor['loadbalancer_id']),
        {
            "pools": [
                pool(
                    delete_healthmonitor['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[],
                    monitors=[]
                )
            ]
        }
    )
    assert_functions.assert_vtm_object_deleted(
        "vtm-{}-pri".format(delete_healthmonitor['loadbalancer_id']),
        "monitors",
        delete_healthmonitor['monitor_id']
    )

