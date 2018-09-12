#!/usr/bin/env python

import base64
from ..environment import env_data
import hashlib
import json
from keystoneclient.v3 import client as keystone_client
from neutronclient.neutron import client as neutron_client
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import subprocess
from time import sleep

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ServicesDirector(object):
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.http = requests.Session()
        self.http.auth = (username, password)
        self.http.verify = False

    def get_instance(self, instance_id):
        response = self.http.get(
            "{}/instance/{}".format(self.base_url, instance_id)
        )
        if response.status_code == 200:
            return response.json()
        else:
            return None

    def get_instance_config(self, instance_id, obj_type, obj_name):
        response = self.http.get(
            "{}/instance/{}/tm/4.0/config/active/{}/{}"
            .format(self.base_url, instance_id, obj_type, obj_name)
        )
        if response.status_code == 200:
            return response.json()
        else:
            return None


class Barbican(object):
    def __init__(self, base_url, project_id):
        self.base_url = base_url
        self.http = requests.Session()
        self.http.headers.update({"X-Project-Id": project_id})
        self.http.verify = False

    def get_public_key(self, container_id):
        try:
            return self._get_key(container_id, "certificate")
        except Exception as e:
            if "{}" in e:
                raise Exception(e.format("public"))
            else:
                raise

    def get_private_key_signature(self, container_id):
        try:
            private_key = self._get_key(container_id, "private_key")
        except Exception as e:
            if "{}" in e:
                raise Exception(e.format("private"))
            else:
                raise
        return base64.b64encode(hashlib.sha256(private_key).digest())

    def generate_keypair(self, name, cn):
        # Generate the keypair
        subprocess.check_output([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", "/tmp/private_key.pem", "-out", "/tmp/certificate.pem",
            "-days", "3650", "-nodes", "-subj", "/CN={}".format(cn)
        ], stderr=subprocess.STDOUT)
        # Upload to Barbican
        secret_refs = {}
        for key_type in ["certificate", "private_key"]:
            response = self.http.post(
                "{}/secrets".format(self.base_url),
                headers={"Content-Type": "application/json"},
                data=json.dumps({
                    "name": "{}-{}".format(name, key_type),
                    "secret_type": "private",
                    "algorithm": "RSA"
                })
            )
            if response.status_code != 201:
                raise Exception("Failed to create certificate in Barbican")
            secret = response.json()
            secret_refs[key_type] = secret['secret_ref']
            with open("/tmp/{}.pem".format(key_type)) as f:
                response = self.http.put(
                    secret_refs[key_type],
                    headers={"Content-Type": "application/octet-stream"},
                    data=f.read()
                )
                if response.status_code != 204:
                    raise Exception("Failed to create certificate in Barbican")
        # Create Barbican container
        response = self.http.post(
            "{}/containers".format(self.base_url),
            headers={"Content-Type": "application/json"},
            data=json.dumps({
                "name": name,
                "type": "certificate",
                "secret_refs": [
                    {"name": k, "secret_ref": v}
                    for k, v in secret_refs.iteritems()
                ]
            })
        )
        if response.status_code != 201:
            raise Exception("Failed to create container in Barbican")
        container_ref = response.json()['container_ref']
        return container_ref[container_ref.rfind("/")+1:]

    def delete_keypair(self, container_id):
        response = self.http.get(
            "{}/containers/{}".format(self.base_url, container_id)
        )
        if response.status_code != 200:
            raise Exception("Failed to delete certificate in Barbican")
        container = response.json()
        self.http.delete(
            "{}/containers/{}".format(self.base_url, container_id)
        )
        for secret in container['secret_refs']:
            self.http.delete(secret['secret_ref'])

    def _get_key(self, container_id, key_type="certificate"):
        response = self.http.get(
            "{}/containers/{}".format(self.base_url, container_id)
        )
        if response.status_code != 200:
            raise Exception("Failed to get container from Barbican")
        container = response.json()
        key_ref = [
            ref['secret_ref'] for ref in container['secret_refs']
            if ref['name'] == key_type
        ][0]
        response = self.http.get(key_ref)
        if response.status_code != 200:
            raise Exception("Failed to get {} key metadata from Barbican")
        key_metadata = response.json()
        content_type = key_metadata['content_types']['default']
        response = self.http.get(
            key_ref,
            headers={"Accept": content_type}
        )
        if response.status_code != 200:
            raise Exception("Failed to get {} key from Barbican")
        return response.text


class Keystone(object):
    def __init__(self, auth_url, username, project_id, password):
        self.auth_url = auth_url
        self.username = username
        self.project_id = project_id
        self.password = password

    def get_client(self):
        return keystone_client.Client(
            username=self.username,
            password=self.password,
            project_id=self.project_id,
            auth_url=self.auth_url
        )

    def get_auth_token(self):
        keystone_client = self.get_client()
        return keystone_client.auth_token


class Nova(object):
    def __init__(self, base_url, keystone):
        self.base_url = base_url.replace("%(tenant_id)s", keystone.project_id)
        self.keystone = keystone

    def get_server(self, server):
        token = self.keystone.get_auth_token()
        response = requests.get(
            "{}/servers?name={}".format(self.base_url, server),
            headers={"X-Auth-Token": token}
        )
        if response.status_code != 200:
            return None
        server_id = response.json()['servers'][0]['id']
        response = requests.get(
            "{}/servers/{}".format(self.base_url, server_id),
            headers={"X-Auth-Token": token}
        )
        if response.status_code != 200:
            return None
        return response.json()['server']

    def create_server(self, name, image, flavor):
        token = self.keystone.get_auth_token()
        data = {"server": {
            "name": name,
            "imageRef": image,
            "flavorRef": flavor,
            "security_groups": [{"name": "default"}],
            "networks": [{"uuid": env_data['test_user_network_id']}]
        }}
        response = requests.post(
            "{}/servers".format(self.base_url),
            headers={
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            },
            data=json.dumps(data)
        )
        if response.status_code >= 300:
            raise Exception("Failed to create server: {}".format(response.text))
        server_id = response.json()['server']['id']
        for _ in xrange(10):
            sleep(20)
            response = requests.get(
                "{}/servers/{}".format(self.base_url, server_id),
                headers={"X-Auth-Token": token}
            )
            if response.status_code == 200:
                data = response.json()['server']
                if data['status'] == "ACTIVE":
                    return (server_id, data['addresses']['private'][0]['addr'])
                elif data['status'] == "ERROR":
                    raise Exception("Failed to get server")
            else:
                raise Exception("Failed to get server")

    def delete_server(self, server_id):
        token = self.keystone.get_auth_token()
        response = requests.delete(
            "{}/servers/{}".format(self.base_url, server_id),
            headers={"X-Auth-Token": token}
        )
        if response.status_code >= 300:
            raise Exception("Failed to delete server {}".format(server_id))

    def pause_server(self, server_id):
        self._server_action(server_id, "pause")

    def unpause_server(self, server_id):
        self._server_action(server_id, "unpause")

    def _server_action(self, server_id, action):
        token = self.keystone.get_auth_token()
        url = "{}/servers/{}/action".format(self.base_url, server_id)
        response = requests.post(
            "{}/servers/{}/action".format(self.base_url, server_id),
            headers={
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            },
            data='{{"{}":null}}'.format(action)
        )
        if response.status_code >= 300:
            raise Exception("Failed to {} server {}: {}\n{}\n{}".format(action, server_id, response.text, url, token))


class Neutron(object):
    def __init__(self, base_url, keystone):
        self.base_url = base_url
        self.keystone = keystone

    def __getattr__(self, name):
        auth_token = self.keystone.get_auth_token()
        neutron = neutron_client.Client(
            '2.0', endpoint_url=self.base_url, token=auth_token
        )
        neutron.format = 'json'
        if not hasattr(neutron, name):
            raise AttributeError(name)
        def func(*args, **kwargs):
            f = getattr(neutron, name)
            return f(*args, **kwargs)
        return func
