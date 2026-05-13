import re

class Vrf():

    def __init__(self, connector, p2p_iface='None'):
        self.p2p_iface = p2p_iface
        self.connector = connector

    def detect_vrf(self):
        output = self.connector.send_command(f"show run interface {self.p2p_iface}")
        rawvrf = re.findall('vrf (member|forwarding) (\S+|\s+)', output)
        if rawvrf:
            vrf = rawvrf[0][1]
        else:
            vrf = 'default'
        return vrf