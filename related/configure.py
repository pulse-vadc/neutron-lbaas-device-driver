#!/usr/bin/env python
#Copyright 2014 Brocade Communications Systems, Inc.  All rights reserved.

import os
import json
import socket
from subprocess import Popen, PIPE, STDOUT, call
from time import sleep

class ConfigFile(dict):
    def __init__(self, name, path):
        self.filename = "%s/%s" % (path, name)
        self._get_current_keys()

    def apply(self):
        with open(self.filename, "w") as config_file:
            for key, value in self.iteritems():
                config_file.write("%s\t%s\n" % (key, value))

    def _get_current_keys(self):
        with open(self.filename) as config_file:
            for line in config_file:
                try:
                    bits = line.split()
                    self[bits[0]] = " ".join(bits[1:])
                except:
                    pass
        

class ReplayData(dict):
    class ReplayDataParameter(object):
        def __init__(self, text):
            words = text.strip().split()
            self.key = words[0]
            self.prefix = words[0].split("!")[0]
            self.value_list = words[1:]
            self.value_str = " ".join(words[1:])

    def __init__(self, text):
        for line in text.split("\n"):
            words = line.split()
            try:
                self[words[0]] = self.ReplayDataParameter(line)
            except IndexError:
                pass
        

def main():
    ZEUSHOME = os.environ.get('ZEUSHOME', '/opt/zeus')
    new_user = None
    uuid_generate_proc = Popen(
        ["%s/zxtm/bin/zcli" % ZEUSHOME],
        stdout=PIPE, stdin=PIPE, stderr=STDOUT
    )
    uuid_generate_proc.communicate(input="System.Management.regenerateUUID")[0]
    call("%s/stop-zeus" % ZEUSHOME)
    with open("/root/config_data") as config_drive:
        user_data = json.loads(config_drive.read())
    global_config = ConfigFile('global.cfg', "%s/zxtm" % ZEUSHOME)
    settings_config = ConfigFile('settings.cfg', "%s/zxtm/conf" % ZEUSHOME)
    security_config = ConfigFile('security', "%s/zxtm/conf" % ZEUSHOME)
    replay_data = ReplayData(user_data['replay_data'])
    for parameter in replay_data.values():
        if parameter.key == "admin!password":
            password_proc = Popen(
                ['z-reset-password'], 
                stdout=PIPE, stdin=PIPE, stderr=STDOUT
            )
            stdout = password_proc.communicate(input="%s\n%s" % (
                parameter.value_str, parameter.value_str
            ))[0]
        elif parameter.key == "monitor_user":
            new_user = { 
                "username": parameter.value_list[0],
                "password": parameter.value_list[1],
                "group": "Guest"
            }
        elif parameter.key in [ 'rest!enabled', 'controlallow' ]:
            settings_config[parameter.key] = parameter.value_str
        elif parameter.key in [ 'developer_mode_accepted', 'nameip' ]:
            global_config[parameter.key] = parameter.value_str
        elif parameter.prefix in [ 'appliance', 'rest', 'control' ]:
            global_config[parameter.key] = parameter.value_str
        elif parameter.key in [ 'access' ]:
            security_config[parameter.key] = parameter.value_str
    global_config.apply()
    settings_config.apply()
    security_config.apply()
    os.remove("%s/zxtm/global.cfg" % ZEUSHOME)
    os.rename(
        "%s/zxtm/conf/zxtms/(none)" % ZEUSHOME, 
        "%s/zxtm/conf/zxtms/%s" % (ZEUSHOME, user_data['hostname'])
    )
    os.symlink(
        "%s/zxtm/conf/zxtms/%s" % (ZEUSHOME, user_data['hostname']), 
        "%s/zxtm/global.cfg" % ZEUSHOME
    )
    call([ "%s/zxtm/bin/sysconfig" % ZEUSHOME, "--apply" ])
    call("%s/start-zeus" % ZEUSHOME)
    if new_user is not None:
        user_proc = Popen(
            ["%s/zxtm/bin/zcli" % ZEUSHOME],
            stdout=PIPE, stdin=PIPE, stderr=STDOUT
        )
        user_proc.communicate(input="Users.addUser %s, %s, %s" % (
            new_user['username'], new_user['password'], new_user['group']
        ))[0]
    if user_data['cluster_join_data'] is not None:
        with open("/tmp/replay_data", "w") as replay_file:
            replay_file.write(user_data['cluster_join_data'])
        if user_data['cluster_target'] is not None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            for _ in xrange(60):
                try:
                    s.connect((user_data['cluster_target'], 9070))
                except socket.error:
                    sleep(2)
                except socket.gaierror:
                    break
            s.close()
        call([ "%s/zxtm/configure" % ZEUSHOME, "--replay-from=/tmp/replay_data" ])


if __name__ == "__main__":
    main()
