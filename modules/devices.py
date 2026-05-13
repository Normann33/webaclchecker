import re
import logging
from modules.network_connector import NetmikoConnector
from modules.normalise import normalise

logger = logging.getLogger(__name__)

class Device():
    def __init__(self, connector: NetmikoConnector, *args) -> None:
        self.connector = connector
        self.is_directly_connected = False

    def get_addr_raw(self, output):
        self.addr_raw = (re.findall('((?:\* |\*via )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|Null)', output))
        return self.addr_raw

    def get_nexthop(self, addr_raw):
        nexthop = addr_raw[0].split()[1]
        return nexthop

    def show_vrf(self, ip, vrf):
        self.output = self.connector.send_command(f'show ip route vrf {vrf} {ip}')
        return self.output

    def detect_next_hop(self, ip, vrf):
        self.vrf = vrf
        if vrf == 'default':
            output = self.connector.send_command(f'show ip route {ip}')
        else:
            output = self.show_vrf(ip, self.vrf)
        addr_raw = self.get_addr_raw(output)
        logger.debug(f'detect_next_hop addr_raw: {addr_raw}')
        for i in addr_raw:
            if 'Null' in i:
                nexthop = None
                return nexthop, self.is_directly_connected
            if 'directly connected' in i or 'attached' in i:
                addr_raw = (re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output))
                nexthop = addr_raw[0]
                self.is_directly_connected = True
                return nexthop, self.is_directly_connected
            elif 'not in table' in i and vrf == 'default':
                output = self.connector.send_command('show ip route 0.0.0.0')
                break
            elif 'not in table' in i and vrf != 'default':
                output = self.connector.send_command(f'show ip route  vrf {self.vrf} 0.0.0.0')
        addr_raw = self.get_addr_raw(output)
        if 'not in table' in addr_raw:
            nexthop = None
            return nexthop, self.is_directly_connected
        else:
            nexthop = self.get_nexthop(addr_raw)
            print (addr_raw, nexthop)
        return nexthop, self.is_directly_connected

    def raw_iface(self, output):
        pattern = re.compile(
            r'(?:directly connected, via |is directly connected, )(\S+)', 
            re.IGNORECASE
        )
        raw_iface = list(set(re.findall(pattern, output)))
        return raw_iface

    def detect_iface(self, nexthop, vrf):
        iface = ''
        if vrf == 'default':
            output = self.connector.send_command(f'show ip route {nexthop}')
        else:
            output = self.connector.send_command(f'show ip route  vrf {vrf} {nexthop}')
        print(output)
        raw_iface = self.raw_iface(output)
        print('raw_iface = ', raw_iface)
        if type(raw_iface[0]) is tuple:
            iface = raw_iface[0][1].strip(',')
        else:
            iface = raw_iface[0].strip(',')
        return iface
    
    def detect_p2p_iface(self, ip):
        output = self.connector.send_command(f'show ip interface brief | inc {ip}').split(' ')
        p2p_iface = output[0]
        return p2p_iface

    def acl_command(self, aclname):
        acl = self.connector.send_command(f'show access-l {aclname}').strip().split('\n')
        return acl

    def detect_acl(self, iface, x):
        #x - in or out
        output = self.connector.send_command(f'show run int {iface}')
        rawacl = re.findall(f'(ip access-group) (\S+|\s+) {x}', output)
        if rawacl:
            aclname = rawacl[0][-1]
            acl = self.acl_command(aclname)
            if 'Extended IP access list' in acl[0]:
                acl.pop(0)
            acl = normalise(acl, self.connector)
            return aclname, acl
        else:
            acl = aclname = 'noacl'
        return aclname, acl
    
    def __str__(self):
        return 'IOS device'

class Arista (Device):
    def __init__(self, ip):
        super().__init__()
        self.ip=ip

    def raw_iface(self, output):
        raw_iface = re.findall('(directly connected,) (\S+|\s+)', output)
        return raw_iface

    def get_addr_raw(self, output):
        self.addr_raw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|Null)", output))
        return self.addr_raw

    def get_nexthop(self, addr_raw):
        try:
            nexthop = addr_raw[1]
        except:
            nexthop = None
        return nexthop

    def acl_command(self, aclname):
        acl = self.connector.send_command(f"show ip access-l {aclname}").strip().split('\n')
        return acl


class Nexus (Device):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
    def __str__(self):
        return 'Nexus device'
    
    def show_vrf(self, ip, vrf):
        self.output = self.connector.send_command(f'show ip route {ip} vrf {vrf}')
        return self.output

    def detect_iface(self, nexthop, vrf):
        self.vrf = vrf
        if self.vrf == 'default':
            output = self.connector.send_command(f'show ip route {nexthop}')
        else:
            output = self.connector.send_command(f'show ip route {nexthop} vrf {self.vrf}')
        raw_iface = re.findall('(\*via) (\S+|\s+) (\S+|\s+)', output)
        iface = raw_iface[0][-1].strip(',')
        return iface
    
    def detect_p2p_iface(self, ip):
        output = self.connector.send_command(f'show ip interface brief vrf all | inc {ip}').split(' ')
        p2p_iface = output[0]
        return p2p_iface