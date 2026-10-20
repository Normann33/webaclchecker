import re
import logging
from modules.network_connector import NetmikoConnector
from modules.normalise import parse_running_config

logger = logging.getLogger(__name__)


# Компилируем тяжелые паттерны ОДИН раз при запуске скрипта
IP_ROUTE_ADDR_PATTERN = re.compile(
    r'((?:\* |\*via )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|\bdirect\b|Null)'
)
PURE_IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# Обратите внимание: убираем динамический f-строковый паттерн из метода detect_acl 
# и делаем его универсальным, захватывая 'in' или 'out' в группу
ACL_GROUP_PATTERN = re.compile(r'ip access-group\s+(\S+)\s+(in|out)', re.IGNORECASE)



class Device():
    def __init__(self, connector: NetmikoConnector, *args) -> None:
        self.connector = connector
        self.is_directly_connected = False
        self.config_context = None # Сюда положим результат parse_running_config
    
    def load_context(self):
        if self.config_context is not None:
            return
        """Скачивает конфигурацию ОДИН раз за сессию."""
        logger.info("Скачивание running-config...")
        try:
            raw_config = self.connector.send_command('show running-config')
        except:
            raw_config = self.connector.send_command('show running-config', max_loops=2000, read_timeout=250)
        self.config_context = parse_running_config(raw_config)

    def get_addr_raw(self, output):
        return IP_ROUTE_ADDR_PATTERN.findall(output)

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
            if any(keyword in i for keyword in ('directly connected', 'attached', 'direct')):
                addr_raw = (re.findall(PURE_IP_PATTERN, output))
                # nexthop = addr_raw[0]
                nexthop = ip
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
            # print (addr_raw, nexthop)
        return nexthop, self.is_directly_connected

    # def raw_iface(self, output):
    #     pattern = re.compile(
    #         r'(?:directly connected, via |is directly connected, )(\S+)', 
    #         re.IGNORECASE
    #     )
    #     raw_iface = list(set(re.findall(pattern, output)))
    #     return raw_iface
    
    def raw_iface(self, output):
        # Универсальный паттерн для поиска интерфейсов Cisco
        # Ищет ключевые слова 'connected' или 'via', за которыми после пробелов 
        # идет известное имя интерфейса (с учетом сокращений) и его номер.
        pattern = re.compile(
            r'(?:connected|via)\s+(?:interface\s+)?'
            r'([a-z]{2,}(?:-[a-z]+)?\d+(?:[\./\d+]+)?(?:\s+\d+)?)',
            re.IGNORECASE
        )
        
        # Использование set для автоматического удаления дубликатов
        interfaces = set()
        
        # Итерация по всем совпадениям через finditer
        for match in re.finditer(pattern, output):
            # Очищаем имя от возможных случайных символов на концах (пробелы)
            iface_name = match.group(1).strip()
            interfaces.add(iface_name)
            
        return list(interfaces)


    def detect_iface(self, nexthop, vrf):
        iface = ''
        if vrf == 'default':
            output = self.connector.send_command(f'show ip route {nexthop}')
        else:
            output = self.connector.send_command(f'show ip route  vrf {vrf} {nexthop}')
        # print(output)
        raw_iface = self.raw_iface(output)
        # print('raw_iface = ', raw_iface)
        if type(raw_iface[0]) is tuple:
            iface = raw_iface[0][1].strip(',')
        else:
            iface = raw_iface[0].strip(',')
        return iface
    
    def detect_p2p_iface(self, target_ip):
        if not self.config_context:
            self.load_context()
        for iface_name, iface_data in self.config_context["interfaces"].items():
            # Проверяем, совпадает ли IP-адрес
            if iface_data.get("ip") == target_ip:
                return iface_name
        # output = self.connector.send_command(f'show ip interface brief | inc {ip}').split()
        # p2p_iface = output[0]
        # return p2p_iface

    def acl_command(self, aclname):
        acl = self.connector.send_command(f'show access-l {aclname}').strip().split('\n')
        return acl

    # def detect_acl(self, iface, x):
    #     #x - in or out
    #     output = self.connector.send_command(f'show run int {iface}')
    #     # rawacl = re.findall(f'(ip access-group) (\S+|\s+) {x}', output)
    #     matches = ACL_GROUP_PATTERN.findall(output) # вернет список кортежей [('ACL_NAME', 'in')]
        
    #     aclname = 'noacl'
    #     for name, direction in matches:
    #         if direction.lower() == x.lower():
    #             aclname = name
    #             break
    #     # if rawacl:
    #     #     aclname = rawacl[0][-1]
    #     if aclname != 'noacl':
    #         acl = self.acl_command(aclname)
            
    #         acl = normalise(acl, self.connector)
    #         return aclname, acl
    #     else:
    #         acl = aclname = 'noacl'
    #     return aclname, acl
    
    def detect_acl(self, iface, direction):
        """Полностью офлайновый метод получения имени и строк ACL."""
        if not self.config_context:
            self.load_context()
            
        iface_data = self.config_context["interfaces"].get(iface, {"in": "noacl", "out": "noacl"})
        acl_name = iface_data.get(direction.lower(), "noacl")
        
        acl_lines = self.config_context["acls"].get(acl_name, [])
        return acl_name, acl_lines
    
    def __str__(self):
        return 'IOS device'

class Arista (Device):
    def __init__(self, connector: NetmikoConnector, *args):
        super().__init__(connector)
        self.connector = connector
        # self.ip=ip

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
    def __init__(self, connector: NetmikoConnector, *args):
        super().__init__(connector)
        self.connector = connector
        # self.ip = ip
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
    
    # def detect_p2p_iface(self, ip):
    #     output = self.connector.send_command(f'show ip interface brief vrf all | inc {ip}').split(' ')
    #     p2p_iface = output[0]
    #     return p2p_iface