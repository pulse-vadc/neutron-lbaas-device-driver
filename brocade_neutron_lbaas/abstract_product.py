#!/usr/bin/env python
#
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

from abc import ABCMeta, abstractmethod
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from threading import Thread
from time import time, sleep
from urllib import quote

from oslo_log import log as logging
LOG = logging.getLogger(__name__)

# Disable warnings for self-signed certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


###############################################################################
#                           Abstract config object classes                    #
###############################################################################

class ConfigObject(object):
    __metadata__ = ABCMeta

    def __init__(self, name, object_type, *args, **kwargs):
        self.name = name
        self._object_type = object_type
        self._process_additional_arguments(**kwargs)

    @abstractmethod
    def to_dict(self, ignore_properties=None):
        return

    @abstractmethod
    def create_from_config_data(self, data):
        return

    def _process_additional_arguments(self, **kwargs):
        protected = ['update', 'delete']
        for field, value in kwargs.iteritems():
            if field not in protected:
                setattr(self, field, value)

    def _poll_for_change(self, field, target_states, error_states, interval=5,
                         timeout=60):
        Thread(target=self._poll, args=(
            field, target_states, error_states, interval, timeout
        )).start()
        # Need to append this to ProductInterface._threads to do a final
        # join() on?

    def _poll(self, field, target_states, error_states, interval, timeout):
        start_time = time()
        response = self.connector("GET")
        print response
        obj = json.loads(response)
        current_value = obj[field]
        setattr(self, field, current_value)
        while current_value not in [target_states]:
            sleep(interval)
            obj = json.loads(self.connector("GET"))
            if obj[field] in error_states:
                raise Exception("Error occured: %s, %s %s is %s" % (
                    self.object_type, self.name, field, obj[field]
                ))
            if obj[field] != current_value:
                current_value = obj[field]
                setattr(self, field, current_value)
            if time() - start_time > timeout:
                raise Exception("Timeout waiting for field change")
        return current_value

    def update(self):
        try:
            if self._is_read_only is True:
                raise Exception("This object is read-only.")
        except AttributeError:
            pass
        try:
            self.connector("PUT", str(self))
        except AttributeError:
            raise Exception("No connection associated with this object.")

    def delete(self):
        try:
            if self._is_deletable is False:
                raise Exception("This object is not deletable.")
        except AttributeError:
            pass
        try:
            if self._is_read_only is True:
                raise Exception("This resource-type is read-only.")
        except AttributeError:
            pass
        self.connector("DELETE")
        try:
            del self._parent_list[self.name]
        except (AttributeError, TypeError):
            pass

    def __str__(self):
        return json.dumps(self.to_dict())

    def __getattr__(self, key):
        if key.startswith("_"):
            return
        object_data = json.loads(self.connector("GET"))
        if "__" in key:
            section, parameter = key.split("__")
        else:
            section = "basic"
            parameter = key
        try:
            return object_data["properties"][section][parameter]
        except TypeError:
            return None


class TextOnlyObject(ConfigObject):
    __metadata__ = ABCMeta

    def __init__(self, name, obj_type, text):
        super(TextOnlyObject, self).__init__(name, obj_type)
        self.text = text

    def to_dict(self):
        return self.text

    def __str__(self):
        return self.text


###############################################################################
#                               Object 'list' classes                         #
###############################################################################

class ConfigObjectList(dict):
    """
    Dictionary of top-level configuration objects.

    Maps object name to configuration object and provides methods for
    manupulating the dictionary.
    """
    __metadata__ = ABCMeta

    def __init__(self, object_class, connector, initialized):
        self.initialized = initialized
        self.object_class = object_class
        self.connector = connector

    @abstractmethod
    def populate_from_instance(self):
        return

    def create(self, name, **kwargs):
        """
        Creates a new top-level configuration object in the dictionary
        and on the product.
        """
        new_object = self.object_class(name, **kwargs)
        try:
            if new_object._is_read_only is True:
                raise Exception("This resource-type is read-only.")
        except AttributeError:
            pass
        self.instantiate(name, obj=new_object)
        self.connector(name, "PUT", str(self[name]))
        return new_object

    def instantiate(self, name, obj=None, config=None):
        """
        Creates a new top-level configuration object in the dictionary.
        """
        if obj:
            new_object = obj
            try:
                if new_object._is_read_only is True:
                    raise Exception("This resource-type is read-only.")
            except AttributeError:
                pass
        elif config:
            new_object = self.object_class(name, config=config)
        else:
            raise Exception("No configuration supplied to instantiate.")
        self[name] = new_object

        def obj_connector(method, data=None, headers=None):
            return self.connector(name, method, data, headers)
        self[name].connector = obj_connector
        self[name]._parent_list = self

    def search(self, **kwargs):
        if not self.initialized:
            raise NotImplementedError(
                "search() not implemented for uninitialized products"
            )
        results = []
        for name, item in self.iteritems():
            for attr, value in kwargs.iteritems():
                try:
                    if getattr(item, attr) == value:
                        results.append(item)
                except AttributeError:
                    pass
        return results

    def get(self, name):
        if self.initialized:
            try:
                return self[name]
            except KeyError:
                return None
        else:
            try:
                def obj_connector(method, data=None, headers=None):
                    return self.connector(name, method, data, headers)
                obj = self.object_class(name, config=self.connector(name))
                obj.connector = obj_connector
                return obj
            except Exception:
                return None

    def list(self):
        if self.initialized:
            return sorted(self)
        else:
            return sorted([
                item['name']
                for item in json.loads(self.connector())['children']
            ])

    def __getattr__(self, name):
        def child_function_wrapper(*args):
            try:
                child = self[args[0]] \
                        if self.initialized else self.get(args[0])
                if child is None:
                    raise KeyError()
            except KeyError:
                raise Exception("Item %s does not exist" % args[0])
            if hasattr(child, name):
                child_function = getattr(child, name)
                child_function_args = args[1:]
                return child_function(*child_function_args)
            else:
                raise AttributeError(name)
        return child_function_wrapper


class SubList(ConfigObjectList):

    def __init__(self, object_class, parent):
        self.object_class = object_class
        self.parent = parent

    def create(self, name, *args, **kwargs):
        self.instantiate(name, *args, **kwargs)
        self.parent.connector("PUT", str(self.parent))

    def instantiate(self, name, *args, **kwargs):
        new_object = self.object_class(name, *args, **kwargs)
        self[name] = new_object
        self[name].parent = self.parent

    def delete(self, name):
        del self[name]
        self.parent.connector("PUT", str(self.parent))

    def update(self):
        self.parent.connector("PUT", str(self.parent))


###############################################################################
#                         Non-standard config object classes                  #
###############################################################################

class ProductInstance(ConfigObject):
    """
    Represents a Brocade product instance.
    """
    __metadata__ = ABCMeta

    def __init__(self, url, username, password, list_class, initialize_config,
                 connectivity_test_url=None):
        self.instance_url = url
        self.connectivity_test_url = connectivity_test_url or url
        # Initialize HTTP connection object
        self.http_session = requests.Session()
        self.http_session.verify = False
        self.http_session.auth = (username, password)

        # Initialize configuration objects that exist in sets:
        #    i.e. everything in self.config_classes!
        obj_lists = []
        for cls, props in self.config_classes.iteritems():
            connector = self.get_list_connector(props['class'], props['path'])
            setattr(
                self,
                props['name'],
                list_class(props['class'], connector, initialize_config)
            )
            setattr(
                self,
                "%s%s" % (props['name'], props['plural']),
                getattr(self, props['name'])
            )
            obj_lists.append(getattr(self, props['name']))
        if initialize_config:
            for obj_list in obj_lists:
                obj_list.populate_from_instance()

    def get_object_connector(self, cls, path):
        """
        Get an HTTP connection object for single-instance objects.
        """
        list_conn = self.get_list_connector(cls, path)

        def obj_conn(method="GET", data=None):
            return list_conn(None, method, data)
        return obj_conn

    def get_list_connector(self, cls, path):
        parent_class = cls.__bases__[0].__name__
        if parent_class == "TextOnlyObject":
            req_headers = {"Content-Type": "application/octet-stream"}
        else:
            req_headers = {"Content-Type": "application/json"}

        def connector(name=None, method="GET", data=None, headers=None):
            http_func = getattr(self.http_session, method.lower())
            url = "%s/%s" % (self.instance_url, path)
            if name:
                url = "%s/%s" % (url, quote(name))
            try:
                modifier = cls._url_modifiers[method]
                if modifier['type'] == "querystring":
                    url = "%s?%s" % (url, modifier['value'])
                else:
                    raise Exception("Unsupported URL modifier")
            except (AttributeError, KeyError):
                pass
            if headers:
                req_headers.update(headers)
            try:
                response = http_func(
                    url,
                    data=data,
                    headers=req_headers
                )
            except Exception as e:
                raise Exception(
                    "Exception '%s' making HTTP request...\nMethod: %s\n"
                    "URL: %s\nHeaders: %s\nBody: %s" % (
                        str(e), method, url, req_headers, data
                    )
            )
            if not 200 <= response.status_code < 300:
                raise Exception(
                    "Invalid HTTP response %s from %s request to %s: %s" % (
                        response.status_code, method, url, response.text
                    ))
            return response.text
        return connector

    def test_connectivity(self):
        try:
            response = self.http_session.get(
                self.connectivity_test_url, timeout=3
            )
        except Exception as e:
            return False
        if response.status_code == 200:
            return True
        return False


###############################################################################
#                  Object factories for common object formats                 #
###############################################################################

def ConfigObjectFactory(class_name, arg_names, parent_class=ConfigObject,
                        params=None):
    def __init__(self, name, config=None, required_fields=True, **kwargs):
        if params:
            for key, value in params.iteritems():
                setattr(self, key, value)
        if config:
            parent_class.__init__(self, name, class_name)
            self.create_from_config_data(config)
        else:
            if required_fields is not False:
                required_args = set(arg_names)
                if required_args.intersection(set(kwargs)) == required_args:
                    parent_class.__init__(self, name, class_name, **kwargs)
                    for key, value in kwargs.items():
                        setattr(self, key, value)
                else:
                    raise Exception(
                        "Required parameter missing: must include %s" % (
                            arg_names
                        )
                    )
    return type(class_name, (parent_class,), {"__init__": __init__})


def TextOnlyObjectFactory(class_name, arg_name):
    def __init__(self, name, config=None, **kwargs):
        if config:
            TextOnlyObject.__init__(self, name, class_name, config)
        elif arg_name in kwargs:
            TextOnlyObject.__init__(self, name, class_name,
                                    kwargs[arg_name])
        else:
            raise Exception("Invalid parameters specified")
    return type(class_name, (TextOnlyObject,), {"__init__": __init__})
