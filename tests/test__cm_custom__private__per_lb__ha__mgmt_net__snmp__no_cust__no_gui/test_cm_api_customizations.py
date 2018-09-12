#!/usr/bin/env python

from ..conftest import dummy_server, nova
from ..environment import env_data
import pytest
from test_listeners import create_http_listener_basic
from test_members import create_pool
from time import sleep


@pytest.fixture()
def update_loadbalancer_bandwidth(neutron, loadbalancer):
    new_bandwidth = env_data['instance_bandwidth'] + 10
    neutron.update_loadbalancer(
        loadbalancer['id'],
        {"loadbalancer": {
            "bandwidth": new_bandwidth
        }}
    )
    yield {
        "loadbalancer_id": loadbalancer['id'],
        "new_bandwidth": new_bandwidth
    }
    neutron.update_loadbalancer(
        loadbalancer['id'],
        {"loadbalancer": {
            "bandwidth": env_data['instance_bandwidth']
        }}
    )


def test_update_loadbalancer_bandwidth(assert_functions, update_loadbalancer_bandwidth):
    context = update_loadbalancer_bandwidth
    assert_functions.assert_sd_instance_bandwidth(
        "vtm-{}-pri".format(context['loadbalancer_id']), context['new_bandwidth']
    )
    assert_functions.assert_sd_instance_bandwidth(
        "vtm-{}-sec".format(context['loadbalancer_id']), context['new_bandwidth']
    )


@pytest.fixture(scope="module")
def create_monitored_member(neutron, dummy_server, create_pool):
    member = neutron.create_lbaas_member(
        create_pool['pool_id'],
        {"member": {
            "address": dummy_server['ip_address'],
            "protocol_port": 80,
            "subnet_id": env_data['test_user_subnet_id']
        }}
    )
    monitor = neutron.create_lbaas_healthmonitor(
        {"healthmonitor": {
            "pool_id": create_pool['pool_id'],
            "type": "PING",
            "max_retries": 2,
            "delay": 1,
            "timeout": 1
        }}
    )
    yield {
        "member_id": member['member']['id'],
        "pool_id": create_pool['pool_id'],
        "server_id": dummy_server['server_id']
    }
    neutron.delete_lbaas_member(member['member']['id'], create_pool['pool_id'])
    neutron.delete_lbaas_healthmonitor(monitor['healthmonitor']['id'])



def test_member_status(assert_functions, create_monitored_member, nova):
    context = create_monitored_member
    assert_functions.assert_member_status_active(
        context['member_id'], context['pool_id']
    )
    nova.pause_server(context['server_id'])
    sleep(5)
    assert_functions.assert_member_status_inactive(
        context['member_id'], context['pool_id']
    )
    nova.unpause_server(context['server_id'])
    sleep(5)
    assert_functions.assert_member_status_active(
        context['member_id'], context['pool_id']
    )
