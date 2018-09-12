#!/usr/bin/env python

env_data = {
    # Barbican connection details
    "barbican_url": "https://<HOST>:9311/v1",

    # Service connection details
    "keystone_url": "https://<HOST>:5000/v3",

    "nova_url": "https://<HOST>:8774/v2/%(tenant_id)s",

    "neutron_url": "https://<HOST>:9696",

    # Credentials for LBaaS user (ie. the user who owns the Services Director/vTMs etc.)
    "lbaas_username": "<LBAAS_USER KEYSTONE USERNAME>",
    "lbaas_project_id": "<LBAAS_USER KEYSTONE PROJECT_ID>",
    "lbaas_password": "<LBAAS_USER KEYSTONE PASSWORD",

    # SD connection details
    "services_director_url": "https://<HOST>:8100/api/tmcm/2.0",
    "services_director_password": "<SERVICES DIRECTOR ADMIN PASSWORD>",
    "services_director_username": "<SERVICES DIRECTOR ADMIN USERNAME>",

    # Credentials to use for carrying out LBaaS CRUD operations (ie. the end-user)
    "test_user_username": "<TEST_USER KEYSTONE USERNAME>",
    "test_user_project_id": "<TEST_USER KEYSTONE PROJECT_ID>",
    "test_user_password": "<TEST_USER KEYSTONE PASSWORD>",

    # Instance spec
    "instance_bandwidth": "<SERVICES DIRECTOR BANDWIDTH ALLOCATION TO EXPECT>",
    "instance_feature_pack": "<SERVICES DIRECTOR FEATURE PACK TO EXPECT>",

    # Test infrastructure
    "test_user_subnet_id": "<NEUTRON_ID OF TEST USER PRIVATE SUBNET>",
    "test_user_network_id": "<NEUTRON_ID OF TEST USER PRIVATE NETWORK>",

    "cirros_image_id": "<GLANCE_ID OF CIRROS IMAGE>",

    # The loadbalancer_id setting below can be used to run a subset of tests
    # against an existing Loadbalancer instance.  This saves the time of
    # provisioning a new vTM HA pair for each test run.  If set to None, a
    # new vTM HA pair will be created and tested against.
    #"loadbalancer_id": "<NEUTRON_ID OF EXISTING LBAAS LOADBALANCER>"
    "loadbalancer_id": None
}
