#!/usr/bin/env python

def traffic_ip_group(name, ipaddresses):
    return {
        "name": name,
        "config": {
            "properties": {
                "basic": {
                    "ipaddresses": ipaddresses
                }
            }
        }
    }


def virtual_server(name, **kwargs):
    # Get defaults for any arguements that aren't specified
    add_x_forwarded_for = kwargs.get("add_x_forwarded_for", True)
    enabled = kwargs.get("enabled", True)
    listen_on_any = kwargs.get("listen_on_any", False)
    listen_on_traffic_ips = kwargs.get("listen_on_traffic_ips", [])
    max_concurrent_connections = kwargs.get("max_concurrent_connections", 0)
    pool = kwargs.get("pool", "discard")
    port = kwargs.get("port", 80)
    protocol = kwargs.get("protocol", "http")
    ssl_decrypt = kwargs.get("ssl_decrypt", False)
    server_cert_default = kwargs.get("server_cert_default", "")
    server_cert_host_mapping = kwargs.get("server_cert_host_mapping", [])

    # Return the virtual server template
    return {   
        "name": name,
        "config": {
            "properties": {
                "basic": {
                    "add_x_forwarded_for": add_x_forwarded_for,
                    "enabled": enabled,
                    "listen_on_any": listen_on_any,
                    "listen_on_traffic_ips": listen_on_traffic_ips,
                    "max_concurrent_connections": max_concurrent_connections,
                    "pool": pool,
                    "port": port,
                    "protocol": protocol,
                    "ssl_decrypt": ssl_decrypt
                },
                "ssl": {
                    "server_cert_default": server_cert_default,
                    "server_cert_host_mapping": server_cert_host_mapping
                }
            }
        }
    }


def pool(name, **kwargs):
    # Get defaults for any arguements that aren't specified
    algorithm = kwargs.get("algorithm", "round_robin")
    nodes_table = kwargs.get("nodes_table", [])
    persistence_class = kwargs.get("persistence_class", "")

    # Return the pool template
    return {
        "name": name,
        "config": {
            "properties": {
                "basic": {
                    "nodes_table": nodes_table,
                    "persistence_class": persistence_class
                },
                "load_balancing": {
                    "algorithm": algorithm
                }
            }
        }
    }


def persistence(name, **kwargs):
    # Get defaults for any arguements that aren't specified
    persistence_type = kwargs.get("type", "ip")
    cookie = kwargs.get("cookie", "")

    # Return the persistence template
    return {
        "name": name,
        "config": {
            "properties": {
                "basic": {
                    "type": persistence_type,
                    "cookie": cookie
                }
            }
        }
    }


def monitor(name, **kwargs):
    # Get defaults for any arguements that aren't specified
    monitor_type = kwargs.get("type", "ping")
    use_ssl = kwargs.get("use_ssl", False)
    timeout = kwargs.get("timeout", 3)
    failures = kwargs.get("failures", 3)
    delay = kwargs.get("delay", 3)
    path = kwargs.get("path", "/")
    status_regex = kwargs.get("status_regex", "(200)")

    # Return the monitor template
    return {
        "name": name,
        "config": {
            "properties": {
                "basic": {
                    "type": monitor_type,
                    "use_ssl": use_ssl,
                    "timeout": timeout,
                    "delay": delay,
                    "failures": failures
                },
                "http": {
                    "path": path,
                    "status_regex": status_regex
                }
            }
        }
    }
