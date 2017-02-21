#!/usr/bin/env python
from distutils.core import setup
import os
from subprocess import check_output

driver_path = None

try:
    cmd_output = check_output(
        ["/usr/bin/locate", "neutron_lbaas/drivers/brocade/driver_v2.py"]
    )
    if len(cmd_output) > 0:
        path_guess = os.path.dirname(cmd_output.split("\n")[0])
        confirm = raw_input(
            "Path located: %s\n"
            "Is this the correct installation path for your Brocade "
            "Neutron LBaaS plugin driver? [y/n]" % path_guess
        )
        if confirm.strip().lower() == "y":
            driver_path = path_guess
except:
    pass

if driver_path is None:
    driver_path = raw_input(
        "Please enter the full path of the directory where the Brocade "
        "Neutron LBaaS plugin driver should be installed: "
    )

setup(
    name="brocade_neutron_lbaas",
    author="Matthew Geldert",
    author_email="mgeldert@brocade.com",
    description="Brocade vADC OpenStack Neutron LBaaS Device Driver",
    long_description=open("README.md").read(),
    version="mitaka",
    url="http://www.brocade.com",
    packages=[
        "brocade_neutron_lbaas",
        "brocade_neutron_lbaas_tenant_customizations_db",
        "brocade_neutron_lbaas.vtm"
    ],
    scripts=[
        "scripts/brocade_lbaas_config_generator",
        "scripts/brocade_lbaas_tenant_customization"
    ],
    data_files=[
        ("/etc/neutron/services/loadbalancer", ["conf/brocade.conf"]),
        (driver_path, ["driver_v2.py"])
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
