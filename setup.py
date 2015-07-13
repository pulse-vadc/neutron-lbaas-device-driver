#!/usr/bin/env python
from distutils.core import setup

setup(name="brocade_neutron_lbaas",
      author="Matthew Geldert",
      author_email="mgeldert@brocade.com",
      description="Brocade vADC OpenStack Neutron LBaaS Device Driver",
      long_description=open("README.md").read(),
      version="0.9b",
      url="http://www.brocade.com",
      packages=["brocade_neutron_lbaas", "brocade_neutron_lbaas.vtm"],
      scripts=["scripts/brocade_lbaas_config_generator"],
      data_files=[("/etc/neutron/services/loadbalancer",
                  ["conf/brocade.conf"])],
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
          "Programming Language :: Python :: 2.7"],
      install_requires=["requests>=2.7.0"])
