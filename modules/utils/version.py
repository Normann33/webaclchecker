import logging
from modules.devices import *
from modules.network_connector import NetmikoConnector

logger = logging.getLogger(__name__)

class Version:

    def __init__(self, connector: NetmikoConnector):
        self.connector = connector
        
    def detect_version(self):
        logger.info('detect_version started')
        try:
            vtext = self.connector.send_command('show version', delay_factor=2).split('\n')[:2]
        except Exception as e:
            try:
                logger.info("Попытка 2: Чтение 'show version' с максимальным коэффициентом задержки (3.0)")
                vtext = self.connector.send_command('show version', delay_factor=3.0)
            except Exception as critical_error:
                logger.critical(f"Критический сбой: Не удалось считать версию устройства после ретрая: {critical_error}")
                raise critical_error
        vtext = ''.join(vtext)
        # return vtext
        if 'NX-OS' in vtext:
            self.connector.set_device_type('cisco_nxos')
            return Nexus(self.connector)
        elif 'Arista' in vtext:
            self.connector.set_device_type('arista_eos')
            return Arista(self.connector)
        # elif 'Adaptive Security Appliance' in vtext:
        #     return Asa(ssh_connect, host_ip)
        else:
            return Device(self.connector)