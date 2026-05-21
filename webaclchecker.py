#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# from datetime import datetime
import re
import os
import logging
# from netmiko import ConnectHandler
from cryptography.fernet import Fernet
# from modules.config import SECRET_KEY, ENABLE_KEY
from modules.findmgmt import findmgmt
import ipaddress
import traceback
import argparse
from modules.network_connector import NetmikoConnector
from modules.utils.version import Version
from modules.utils.vrf import Vrf
from modules.devices import *
from modules.normalise import normalise
from modules.compare import compare
from modules.asa import Asa
from dotenv import load_dotenv
import time

start = time.perf_counter()

logger = logging.getLogger(__name__)
load_dotenv()

username = os.getenv('CISCOUSER')
password = os.getenv('CISCOPASS')

# cipher_suite = Fernet(SECRET_KEY)

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network


def find_host_name(connector):
    is_enabled = True
    command = connector.find_prompt()
    if '>' in command:
        is_enabled = False
    hostname = str(connector.find_prompt())[:-1]
    return is_enabled, hostname

enable = '123' # Temporary!!!
dstnexthop = '' # Temporary!!!

vrf = 'default' # Temporary!!!
src = '' # Temporary!!!
dst = '' # Temporary!!!
dst_port = '22'# Temporary!!!
prot = 'tcp'# Temporary!!!
gw = '127.0.0.1'

def run(username, password, prot, src, dst, dst_port, gw, vrf):
    results = []
    while True:
        print('running...')
        is_first_hop = False
        dstnexthop = '' # Temporary!!!
        result_index = 0
        p2p_iface = ''
        
        with NetmikoConnector(
            host=gw,
            username=username,
            password=password,
            secret=enable,
            device_type='',
            port=''
        ) as connector:
            
            version = Version(connector)
            device = version.detect_version()
            
            hostname_find_start = time.perf_counter()
            is_enabled, hostname = find_host_name(connector)
            if is_enabled == False:
                connector.enable()
                print(str(connector.find_prompt()))
            yield {'index': result_index,'hostname': hostname}
            print(hostname)
            hostname_find_end = time.perf_counter()
            print(f"⏱ find_host_name Выполнено за {hostname_find_end - hostname_find_start:.3f} сек")
            
            # is_first_hop = False
            if is_first_hop == False:
                p2p_iface = device.detect_p2p_iface(dstnexthop)
                print(p2p_iface)
                v = Vrf(connector, p2p_iface)
                vrf = v.detect_vrf()
            yield {'index': result_index,'vrf': vrf}

            # Detect source interface
            nexthop, idc = device.detect_next_hop(src, vrf)
            if nexthop == None:
                yield {'index': result_index, 'endmessage': 'No further route in this VRF'}
                return results
            srciface = device.detect_iface(nexthop, vrf)
            yield {'index': result_index, 'srciface': srciface}
            
            # Detect access-list on source interface
            try:
                aclname, acl = device.detect_acl(srciface, 'in')
                yield {'index': result_index, 'srcaclname': aclname}
            except Exception:
                traceback.print_exc()
                exit() 
            
            # Check if we can pass access-list
            if acl == 'noacl':
                yield {'index': result_index, 'srcresult': 'PASSED, no access-list'}
            else:
                yield {'index': result_index, 'srcresult': compare(acl, src, dst, dst_port, prot)}
            # Detect outgoing interface and next hop
            device.is_directly_connected = False
            dstnexthop, dstidc = device.detect_next_hop(dst, vrf)
            if dstnexthop == None:
                yield {'index': result_index, 'endmessage': 'No further route in this VRF'}
            dstiface = device.detect_iface(dstnexthop, vrf)
            yield {'index': result_index, 'dstiface': dstiface}

            # Detect access-list on destination interface
            try:
                aclname, acl = device.detect_acl(dstiface, 'out')
                yield {'index': result_index, 'dstaclname': aclname}
            except Exception:
                print('Wrong destination ip!')
                exit()

            # Check if we can pass access-list
            if acl == 'noacl':
                yield {'index': result_index, 'dstresult': 'PASSED, no access-list'}
            else:
                yield {'index': result_index, 'dstresult': compare(acl, src, dst, dst_port, prot)}
            
            # If destination is directly connected - finish
            if dstidc == True:
                yield {'index': result_index, 'endmessage': 'Target is directly connected'}
                result_index += 1
                print(results)
                return results
            
            # Detect management ip of next hop
            nexthost = findmgmt(dstnexthop)
            yield {'index': result_index, 'nexthop': nexthost}
            is_first_hop = False
            v = Vrf(connector, p2p_iface)
            result_index += 1
        gw = nexthost
        # exit()

if __name__ == '__main__':
    for result in run(username, password, prot, src, dst, dst_port, gw, vrf):
        print(result)
        end = time.perf_counter()
        print(f"⏱ Выполнено за {end - start:.3f} сек")
