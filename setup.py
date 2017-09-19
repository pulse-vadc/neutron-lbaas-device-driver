#!/usr/bin/env python
from distutils.core import setup
import os
from subprocess import check_output

driver_path = None

try:
    cmd_output = check_output(
        ["/usr/bin/locate", "neutron_lbaas/drivers/"]
    )
    if len(cmd_output) > 0:
        path_guess = os.path.dirname(cmd_output.split("\n")[0])
        path_guess += "/pulse"
        confirm = raw_input(
            "Install Pulse Neutron LBaaS plugin into '{}'? [y/n] "
            "".format(path_guess)
        )
        if confirm.strip().lower() == "y":
            driver_path = path_guess
except:
    pass

if driver_path is None:
    driver_path = raw_input(
        "Please enter the full path of the directory where the Pulse "
        "Neutron LBaaS plugin should be installed: "
    )

if not os.path.exists(driver_path):
    try:
        os.makedirs(driver_path)
    except IOError as e:
        print "Failed to install plugin to '{}': {}".format(driver_path, e)

setup(
    name="pulse_neutron_lbaas",
    author="Matthew Geldert",
    author_email="mgeldert@pulsesecure.net",
    description="Pulse vADC OpenStack Neutron LBaaS Device Driver",
    long_description=open("README.md").read(),
    version="octa",
    url="https://www.pulsesecure.net",
    packages=[
        "pulse_neutron_lbaas",
        "pulse_neutron_lbaas_tenant_customizations_db"
    ],
    scripts=[
        "scripts/pulse_lbaas_config_generator",
        "scripts/pulse_lbaas_tenant_customization"
    ],
    data_files=[
        ("/etc/neutron", ["conf/pulse_vtm_lbaas.conf"]),
        (driver_path, ["driver_v2.py"]),
        (driver_path, ["__init__.py"])
    ],
    license="Apache Software License",
    platforms=["Linux"],
    classifiers=[
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Environment :: OpenStack",
        "License :: OSI Approved :: Apache Software License"
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7"
    ]
)
