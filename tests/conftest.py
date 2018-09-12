#!/usr/bin/env python

from lib.assert_functions import AssertFunctions
from lib.connectors import Keystone, Neutron, Barbican, Nova
from environment import env_data
import pytest
from time import sleep


@pytest.fixture(scope="session")
def assert_functions():
    return AssertFunctions(env_data)


@pytest.fixture(scope="session")
def neutron():
    keystone = Keystone(
        env_data['keystone_url'],
        env_data['test_user_username'],
        env_data['test_user_project_id'],
        env_data['test_user_password']
    )
    return Neutron(env_data['neutron_url'], keystone)


@pytest.fixture(scope="session")
def nova():
    keystone = Keystone(
        env_data['keystone_url'],
        env_data['test_user_username'],
        env_data['test_user_project_id'],
        env_data['test_user_password']
    )
    return Nova(env_data['nova_url'], keystone)


@pytest.fixture(scope="session")
def barbican():
    return Barbican(
        env_data['barbican_url'],
        env_data['test_user_project_id']
    )


@pytest.fixture(scope="session")
def loadbalancer(neutron):
    if env_data['loadbalancer_id'] is None:
        print "Creating a new loadbalancer"
        loadbalancer = neutron.create_loadbalancer(
            {"loadbalancer": {
                "name": "MyTestLB1",
                "vip_subnet_id": env_data['test_user_subnet_id']
            }}
        )
        loadbalancer_id = loadbalancer['loadbalancer']['id']
        for i in xrange(0, 30):
            sleep(10)
            loadbalancer = neutron.show_loadbalancer(loadbalancer_id)
            if loadbalancer['loadbalancer']['provisioning_status'] == "ACTIVE":
                break
            elif loadbalancer['loadbalancer']['provisioning_status'] == "ERROR":
                pytest.exit("Abandoning tests: failed to create loadbalancer")
        sleep(20)
    else:
        print "Using existing loadbalancer"
        try:
            loadbalancer = neutron.show_loadbalancer(
                env_data['loadbalancer_id']
            )
        except Exception as e:
            pytest.exit(
                "Could not retrieve existing loadbalancer '{}': {}"
                .format(env_data['loadbalancer_id'], e)
            )
    yield loadbalancer['loadbalancer']


@pytest.fixture(scope="session")
def dummy_server():
    keystone = Keystone(
        env_data['keystone_url'],
        env_data['test_user_username'],
        env_data['test_user_project_id'],
        env_data['test_user_password']
    )
    nova = Nova(env_data['nova_url'], keystone)
    server_id, ip_addr = nova.create_server("Dummy1", env_data['cirros_image_id'], "1")
    yield {
        "server_id": server_id,
        "ip_address": ip_addr
    }
    nova.delete_server(server_id)
