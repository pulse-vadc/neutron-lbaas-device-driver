#!/usr/bin/python
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
#
#Usage
#Set OpenStack credentials(source admin/ demo) before executing script

cd /home

DATE=`date +%Y_%m_%d_%H_%M_%S`
TSR_DIR="brocade_lbaas_support_"$DATE
mkdir $TSR_DIR


cp /etc/neutron/services/loadbalancer/brocade.conf /home/$TSR_DIR
cp /etc/neutron/neutron_lbaas.conf /home/$TSR_DIR
cp /var/log/neutron/server.log /home/$TSR_DIR

sed -i 's/password=.*/password=####/' /home/$TSR_DIR/brocade.conf
sed -i 's/openstack_password=.*/openstack_password=####/' /home/$TSR_DIR/brocade.conf

echo " " >> /home/$TSR_DIR/output.txt
echo "### df -h" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
df -h >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### free -h" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
free -h >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### cat cpuinfo" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
cd /proc
cat cpuinfo >> /home/$TSR_DIR/output.txt
cd -
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### ip addr" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
ip addr >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### ip route" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
ip route >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### nova list" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
nova list >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### neutron port-list" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
neutron port-list >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "### neutron security-group-list" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
neutron security-group-list >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt
echo "--------------------------------------------------------" >> /home/$TSR_DIR/output.txt
echo " " >> /home/$TSR_DIR/output.txt


tar -cvf $TSR_DIR.tar /home/$TSR_DIR

