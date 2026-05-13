import logging
from modules.devices import *
from modules.network_connector import NetmikoConnector

logger = logging.getLogger(__name__)

class Version:

    def __init__(self, connector: NetmikoConnector):
        self.connector = connector
        
    def detect_version(self):
        logger.info('detect_version started')
        vtext = self.connector.send_command('show version').split('\n')[:2]
        vtext = ''.join(vtext)
        # return vtext
        if 'NX-OS' in vtext:
            return Nexus(Device)
        elif 'Arista' in vtext:
            return Arista(Device)
        # elif 'Adaptive Security Appliance' in vtext:
        #     return Asa(ssh_connect, host_ip)
        else:
            return Device(self.connector)