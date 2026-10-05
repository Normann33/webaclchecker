import logging
from modules.linesplit import LineSplit
import ipaddress
import traceback

logger = logging.getLogger(__name__)

addr = ipaddress.ip_address
net = ipaddress.ip_network

l1 = LineSplit()

def check_mask(ip_str, network_line):
        # Преобразуем строки в объекты IP
        network_line = network_line.split('/')
        network_str = network_line[0]
        mask_str = network_line[1]
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_address(network_str)
        mask = ipaddress.ip_address(mask_str)

        # Получаем побитовые представления
        ip_bin = int(ip)
        network_bin = int(network)
        mask_bin = int(mask)

        # Проверяем, попадает ли IP в сеть с использованием маски
        return (ip_bin & ~mask_bin) == (network_bin & ~mask_bin)

def check_ip(ip, network):
    '''Check if ip address belongs to network'''
    try:
        return (addr(ip) in net(network))
    except:
        return check_mask(ip, network)
    
def match_line(line, src, dst, dst_port, prot):
    if 'permit' not in line and 'deny' not in line:
        return False
    if 'established' in line:
        return False

    line_parts = line.split()
    action_index = -1
    for idx, part in enumerate(line_parts):
        if part in ['permit', 'deny']:
            action_index = idx
            break
            
    if action_index == -1 or action_index + 1 >= len(line_parts):
        return False
        
    acl_prot = line_parts[action_index + 1]
    if acl_prot != 'ip' and acl_prot != prot:
        return False

    try:
        acl_src, acl_dst = l1.acl_addr(line)
    except Exception:
        return False

    if not check_ip(src, acl_src) or not check_ip(dst, acl_dst):
        return False

    if acl_prot != 'ip':
        if not any(op in line for op in ['eq', 'range', 'gt', 'lt']):
            return True
        if not l1.check_port(line, dst_port):
            return False

    return True

def find_match(acl, src, dst, dst_port, prot):
# Ищем совпадения в access-list-e
    logger.info('find_match started')
    for line in acl:
        if not line:
            continue
        try:
            if match_line(line, src, dst, dst_port, prot):
                if 'permit' in line:
                    return line
        except Exception:
            traceback.print_exc()
            logger.error(f'Не могу разобрать строку {line}')
            pass
    else:
        line = '99999 deny ip any any'
        return line        
    
if __name__ == '__main__':
    find_match(acl, src, dst, dst_port, prot)