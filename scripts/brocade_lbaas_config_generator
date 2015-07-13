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

import sys


class Question(object):
    class Answer(object):
        def __init__(self, value, next_link):
            self.value = value
            self.next_link = next_link

    def __init__(self, text, section, field_name, options=None, default=None,
                 var_type=None, next_link=None):
        self.text = text
        self.section = section
        self.field_name = field_name
        self.options = options
        self.default = default
        self.var_type = var_type
        self.next_link = next_link

    def ask(self):
        print "\n%s" % self.text
        if self.options:
            for i, opt in enumerate(self.options, 1):
                print "\t%s) %s" % (i, opt['name'])
            ans = 0
            while ans < 1 or ans > len(self.options):
                try:
                    ans = int(raw_input("Choice: "))
                except ValueError:
                    ans = 0
                    print "Invalid input, please enter a number."
            return self.Answer(
                self.options[ans - 1]['value'],
                self.options[ans - 1]['next_link']
            )
        else:
            while True:
                if self.default:
                    ans = raw_input(
                        "Input%s:" % " (Default=%s)" % self.default or ""
                    ) or self.default
                else:
                    ans = ""
                    while ans == "":
                        ans = raw_input("Input: ")
                        if ans == "":
                            print "This setting has no default; " + \
                                  "please enter a value: "
                if self.var_type is not None:
                    try:
                        self.var_type(ans)
                        return self.Answer(ans, self.next_link)
                    except ValueError:
                        print "Invalid input: must be %s" % self.var_type
                else:
                    return self.Answer(ans, self.next_link)


question_chain = {
    "start": [
        Question("Which Brocade product do you wish to use?", "lbaas_settings",
                 "product", options=[
                     {"name": "vTM", "value": "VTM",
                      "next_link": "vtm_model"}
    ],
    "vtm_model": [
        Question("What deployment model are you using?", "lbaas_settings",
                 "deployment_model", options=[
                     {"name": "Shared Instances", "value": "SHARED",
                      "next_link": "vtm_shared"},
                     {"name": "Private Instances", "value": None,
                      "next_link": "vtm_private"}])
    ],
    "vtm_shared": [
        Question("Please provide a comma-seperated list of all vTM "
                 "hostnames in your cluster:", "lbaas_settings",
                 "admin_servers"),
        Question("What is the username for the vTM cluster admin user?",
                 "vtm_settings", "username", default="admin"),
        Question("What is the password for the vTM cluster admin user?",
                 "vtm_settings", "password"),
        Question("Please provide a comma-seperated list of Neutron port "
                 "IDs that represent the interfaces for each vTM on which "
                 "VIPs will listen:", "lbaas_settings", "ports"),
        Question("How many passive Traffic IP Group members should there be?",
                 "lbaas_settings", "passive_vtms",
                 next_link="vtm_all_vtmsettings")
    ],
    "vtm_private": [
        Question("Which deployment model do you wish to use?",
                 "lbaas_settings", "deployment_model", options=[
                     {"name": "A vTM per tenant",
                      "value": "PER_TENANT", "next_link": None},
                     {"name": "A vTM per loadbalancer object (VIP)",
                      "value": "PER_LOADBALANCER", "next_link": None}]),
        Question("How should vTMs be deployed?", "lbaas_settings",
                 "deploy_ha_pairs", options=[
                     {"name": "As single instances",
                      "value": False, "next_link": None},
                     {"name": "As HA pairs",
                      "value": True, "next_link": None}]),
        Question("Please provide a comma-seperated list of SSC hostnames:",
                 "lbaas_settings", "admin_servers"),
        Question("What is the Glance ID of the vTM image to use?",
                 "lbaas_settings", "image_id"),
        Question("What is the Nova ID of the flavor to use for vTMs?",
                 "lbaas_settings", "flavor_id"),
        Question("What domain name should be used for vTM instances?",
                 "lbaas_settings", "vtm_domain"),
        Question("Which management mode should be used?", "lbaas_settings",
                 "management_mode", options=[
                     {"name": "Dedicated management network",
                      "value": "MGMT_NET", "next_link": "vtm_private_mgmtnet"},
                     {"name": "Floating IP addresses", "value": "FLOATING_IP",
                      "next_link": "vtm_private_flip"}])
    ],
    "vtm_private_mgmtnet": [
        Question("What is the Neutron ID of the management network?",
                 "lbaas_settings", "management_network",
                 next_link="vtm_private_dnssettings")
    ],
    "vtm_private_flip": [
        Question("What is the Neutron ID of the network on which to raise "
                 "the floating IPs?", "lbaas_settings", "management_network",
                 next_link="vtm_private_dnssettings")
    ],
    "vtm_private_dnssettings": [
        Question("Which name resolution plugin should be used?",
                 "lbaas_settings", "name_resolution_plugin", options=[
                     {"name": "None", "value": "noop",
                      "next_link": "vtm_private_sscsettings"},
                     {"name": "/etc/hosts", "value": "hosts",
                      "next_link": "vtm_private_sscsettings"},
                     {"name": "Designate", "value": "designate",
                      "next_link": "vtm_private_designatesettings"}]),
    ],
    "vtm_private_designatesettings": [
        Question("What is the endpoint of the Designate API service?",
                 "lbaas_designate_settings", "endpoint"),
        Question("What is the Designate ID of the zone to use?",
                 "lbaas_designate_settings", "zone",
                 next_link="vtm_private_sscsettings")
    ],
    "vtm_private_sscsettings": [
        Question("What is the username of the SSC admin user?",
                 "ssc_settings", "username", default="admin"),
        Question("What is the password of the SSC admin user?",
                 "ssc_settings", "password"),
        Question("Which TCP port does the SSC REST API listen on?",
                 "ssc_settings", "rest_port", default="8000", var_type=int),
        Question("Which SSC API version should be used?",
                 "ssc_settings", "api_version", default="1.5", var_type=float),
        Question("How much bandwidth (Mbps) should each vTM be allocated?",
                 "ssc_settings", "bandwidth", var_type=int),
        Question("Which SSC feature pack should each vTM use?",
                 "ssc_settings", "feature_pack"),
        Question("Which SSC version resource should each vTM use?",
                 "ssc_settings", "version_resource"),
        Question("Which SSC FLA license resource should each vTM use?",
                 "ssc_settings", "fla_license",
                 next_link="vtm_private_vtmsettings")
    ],
    "vtm_private_vtmsettings": [
        Question("Give tenants read-only access to the vTM GUI?",
                 "vtm_settings", "gui_access", options=[
                     {"name": "Yes", "value": True, "next_link": None},
                     {"name": "No", "value": False, "next_link": None}]),
        Question("What timezone are the vTMs in?",
                 "vtm_settings", "timezone", default="Europe/London"),
        Question("Please provide a comma-seperated list of your nameservers:",
                 "vtm_settings", "nameservers",
                 next_link="vtm_all_vtmsettings"),
    ],
    "vtm_all_vtmsettings": [
        Question("Which TCP port does the vTM REST API listen on?",
                 "vtm_settings", "rest_port", default="9070",
                 var_type=int),
        Question("Which vTM API version should be used?",
                 "vtm_settings", "api_version", default="3.3",
                 var_type=float, next_link="vtm_all_oscredentials")
    ],
    "vtm_all_oscredentials": [
        Question("What is the username for the OpenStack admin user?",
                 "lbaas_settings", "openstack_username", default="admin"),
        Question("What is the password for the OpenStack admin user?",
                 "lbaas_settings", "openstack_password")
    ]
}


def format_config(config_data):
    file_text = ""
    for section, parameters in config_data.iteritems():
        file_text += "[%s]\n" % section
        for key, value in sorted(parameters.iteritems()):
            file_text += "%s=%s\n" % (key, value)
        file_text += "\n"
    return file_text


def execute_question_chain(index):
    config_data = {}
    for question in question_chain[index]:
        answer = question.ask()
        if answer.value is not None:
            try:
                config_data[question.section][question.field_name] = \
                    answer.value
            except KeyError:
                config_data[question.section] = {}
                config_data[question.section][question.field_name] = \
                    answer.value
        if answer.next_link is not None and answer.next_link != index:
            execute_question_chain(answer.next_link)
    return config_data


if __name__ == "__main__":
    config_data = execute_question_chain("start")
    config_text = format_config(config_data)
    try:
        with open(sys.argv[1], "w") as config_file:
            config_file.write(config_text)
        print "\nOutput successfully written to %s" % sys.argv[1]
    except IndexError:
        print "\n%s" % config_text
    except Exception as e:
        print "\nError occured writing config to file: %s" % e
        print "Dumping to screen instead...\n"
        print config_text
