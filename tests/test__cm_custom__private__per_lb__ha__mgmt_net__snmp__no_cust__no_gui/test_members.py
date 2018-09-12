#!/usr/bin/env python

from ..environment import env_data
import pytest
from test_listeners import create_http_listener_basic
from test_pools import create_round_robin_pool
from ..lib.vtm_object_templates import pool


@pytest.fixture(scope="module")
def create_pool(neutron, create_http_listener_basic):
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


@pytest.fixture(scope="module")
def create_member_basic(neutron, create_pool):
    member_1 = neutron.create_lbaas_member(
        create_pool['pool_id'],
        {"member": {
            "address": "10.0.0.1",
            "protocol_port": 80,
            "subnet_id": env_data['test_user_subnet_id']
        }}
    )
    member_2 = neutron.create_lbaas_member(
        create_pool['pool_id'],
        {"member": {
            "address": "10.0.0.2",
            "protocol_port": 80,
            "subnet_id": env_data['test_user_subnet_id']
        }}
    )
    yield {
        "member_1_id": member_1['member']['id'],
        "member_2_id": member_2['member']['id'],
        "pool_id": create_pool['pool_id'],
        "loadbalancer_id": create_pool['loadbalancer_id'],
    }


def test_create_member_basic(assert_functions, create_member_basic):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(create_member_basic['loadbalancer_id']),
        {
            "pools": [
                pool(
                    create_member_basic['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[
                        {
                            "node": "10.0.0.1:80",
                            "priority": 1,
                            "state": "active",
                            "weight": 1
                        },
                        {
                            "node": "10.0.0.2:80",
                            "priority": 1,
                            "state": "active",
                            "weight": 1
                        }
                    ]
                )
            ]
        }
    )


@pytest.fixture()
def update_member_set_admin_down(neutron, create_member_basic):
    neutron.update_lbaas_member(
        create_member_basic['member_1_id'], 
        create_member_basic['pool_id'],
        {"member": {
            "admin_state_up": False
        }}
    )
    yield {
        "pool_id": create_member_basic['pool_id'],
        "loadbalancer_id": create_member_basic['loadbalancer_id'],
    }


def test_update_member_set_admin_down(
    assert_functions,
    update_member_set_admin_down
):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(update_member_set_admin_down['loadbalancer_id']),
        {
            "pools": [
                pool(
                    update_member_set_admin_down['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[
                        {
                            "node": "10.0.0.1:80",
                            "priority": 1,
                            "state": "disabled",
                            "weight": 1
                        },
                        {
                            "node": "10.0.0.2:80",
                            "priority": 1,
                            "state": "active",
                            "weight": 1
                        }
                    ]
                )
            ]
        }
    )


@pytest.fixture()
def update_member_set_weight(neutron, create_member_basic):
    neutron.update_lbaas_member(
        create_member_basic['member_2_id'], 
        create_member_basic['pool_id'],
        {"member": {
            "weight": 3
        }}
    )
    yield {
        "pool_id": create_member_basic['pool_id'],
        "loadbalancer_id": create_member_basic['loadbalancer_id'],
    }


def test_update_member_set_weight(assert_functions, update_member_set_weight):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(update_member_set_weight['loadbalancer_id']),
        {
            "pools": [
                pool(
                    update_member_set_weight['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[
                        {
                            "node": "10.0.0.1:80",
                            "priority": 1,
                            "state": "disabled",
                            "weight": 1
                        },
                        {
                            "node": "10.0.0.2:80",
                            "priority": 1,
                            "state": "active",
                            "weight": 3
                        }
                    ]
                )
            ]
        }
    )


@pytest.fixture()
def delete_member(neutron, create_member_basic):
    neutron.delete_lbaas_member(
        create_member_basic['member_1_id'], create_member_basic['pool_id']
    )
    neutron.delete_lbaas_member(
        create_member_basic['member_2_id'], create_member_basic['pool_id']
    )
    yield {
        "pool_id": create_member_basic['pool_id'],
        "loadbalancer_id": create_member_basic['loadbalancer_id'],
    }


def test_delete_member(assert_functions, delete_member):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(delete_member['loadbalancer_id']),
        {
            "pools": [
                pool(
                    delete_member['pool_id'],
                    algorithm="weighted_round_robin",
                    nodes_table=[]
                )
            ]
        }
    )
