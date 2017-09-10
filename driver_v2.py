# Copyright 2017 Brocade Communications Systems, Inc.  All rights reserved.
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
# Matthew Geldert (mgeldert@pulsesecure.net), Pulse Secure, LLC
#

from pulse_neutron_lbaas import device_driver
from neutron_lbaas.drivers import driver_base
import threading


class PulseLoadBalancerDriver(driver_base.LoadBalancerBaseDriver):

    def __init__(self, plugin):
        super(PulseLoadBalancerDriver, self).__init__(plugin)
        self.load_balancer = PulseLoadBalancerManager(self)
        self.listener = PulseListenerManager(self)
        self.pool = PulsePoolManager(self)
        self.member = PulseMemberManager(self)
        self.health_monitor = PulseHealthMonitorManager(self)
        self.l7policy = PulseL7PolicyManager(self)
        self.l7rule = PulseL7RuleManager(self)
        self.device_driver = device_driver.PulseDeviceDriverV2(plugin)


class PulseLoadBalancerManager(driver_base.BaseLoadBalancerManager):
    def create(self, context, obj):
        thread = threading.Thread(target=self._create, args=(context, obj))
        thread.start()

    def _create(self, context, obj):
        try:
            self.driver.device_driver.create_loadbalancer(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_loadbalancer(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_loadbalancer(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)

    def refresh(self, context, lb_obj):
        self.driver.device_driver.refresh(lb_obj)

    def stats(self, context, lb_obj):
        return self.driver.device_driver.stats(lb_obj)


class PulseListenerManager(driver_base.BaseListenerManager):
    def create(self, context, obj):
        try:
            self.driver.device_driver.create_listener(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_listener(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_listener(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)


class PulsePoolManager(driver_base.BasePoolManager):
    def create(self, context, obj):
        try:
            self.driver.device_driver.create_pool(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_pool(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_pool(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)


class PulseMemberManager(driver_base.BaseMemberManager):
    def create(self, context, obj):
        try:
            self.driver.device_driver.create_member(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_member(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_member(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)


class PulseHealthMonitorManager(driver_base.BaseHealthMonitorManager):
    def create(self, context, obj):
        try:
            self.driver.device_driver.create_healthmonitor(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_healthmonitor(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_healthmonitor(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)


class PulseL7PolicyManager(driver_base.BaseL7PolicyManager):
    def create(self, context, obj):
        try:
            self.driver.device_driver.create_l7_policy(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_l7_policy(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_l7_policy(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)


class PulseL7RuleManager(driver_base.BaseL7RuleManager):
    def create(self, context, obj):
        try:
            self.driver.device_driver.create_l7_rule(obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def update(self, context, old_obj, obj):
        try:
            self.driver.device_driver.update_l7_rule(obj, old_obj)
            self.successful_completion(context, obj)
        except Exception:
            self.failed_completion(context, obj)

    def delete(self, context, obj):
        try:
            self.driver.device_driver.delete_l7_rule(obj)
        except Exception:
            pass
        self.successful_completion(context, obj, delete=True)
