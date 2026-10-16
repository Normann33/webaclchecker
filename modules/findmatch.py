import logging
import re
from modules.linesplit import LineSplit
import ipaddress
import traceback

logger = logging.getLogger(__name__)

addr = ipaddress.ip_address
net = ipaddress.ip_network

l1 = LineSplit()

# ACL_STRUCTURE_PATTERN = re.compile(
#     r'(?P<action>permit|deny)\s+'
#     r'(?P<proto>\S+)\s+'
#     r'(?P<src>object-group\s+\S+|host\s+\S+|any\d*|\S+\s+\S+|\S+)(?:\s+(?:eq|range|gt|lt|neq)\s+\S+)?\s+'
#     r'(?P<dst>object-group\s+\S+|host\s+\S+|any\d*|\S+\s+\S+|\S+)'
# )
ACL_STRUCTURE_PATTERN = re.compile(
    r'(?P<action>permit|deny)\s+'
    r'(?P<proto>object-group\s+\S+|\S+)\s+'
    r'(?P<src>object-group\s+\S+|host\s+\S+|any\d*|\S+\s+\S+|\S+)(?:\s+(?:eq|range|gt|lt|neq)\s+\S+)?\s+'
    r'(?P<dst>object-group\s+\S+|host\s+\S+|any\d*|\S+\s+\S+|\S+)'
)


def is_valid_netmask(mask_bin):
    """
    Проверяет, является ли бинарная маска валидной стандартной маской подсети
    (строгая последовательность единиц, переходящая в нули).
    """
    # Инвертируем биты и прибавляем 1. Для валидной маски (например, 255.255.255.0)
    # это действие превратит её в степень двойки, у которой в бинарном виде только одна 1.
    # Пример: ~255.255.255.0 = 0.0.0.255. Прибавляем 1 = 0.0.1.0 (ровно один бит).
    if mask_bin == 0:  # Маска 0.0.0.0 валидна как any
        return True
    # Побитовое свойство проверки на степень двойки: (x & (x - 1)) == 0
    inv = (~mask_bin) & 0xFFFFFFFF
    check = inv + 1
    return (check & (check - 1)) == 0


def ip_matches_rule(target_ip_str, rule_address_string):
    """
    Проверяет, входит ли target_ip_str в подсеть rule_address_string.
    Полностью поддерживает экстремальные и разрывные маски (3.255.255.255, 0.3.0.255).
    """
    parts = rule_address_string.strip().split()
    
    # 1. Обработка формата CIDR (например, 10.1.1.0/24)
    if len(parts) == 1 and '/' in parts:
        try:
            return ipaddress.ip_address(target_ip_str) in ipaddress.ip_network(parts, strict=False)
        except Exception:
            return False

    # 2. Обработка формата IP + Маска (обычная, wildcard или экстремальная)
    if len(parts) == 2:
        net_str, mask_str = parts[0], parts[1]
        try:
            ip_bin = int(ipaddress.ip_address(target_ip_str))
            net_bin = int(ipaddress.ip_address(net_str))
            mask_bin = int(ipaddress.ip_address(mask_str))
            
            # Автоопределение типа маски на основе ее структуры
            if is_valid_netmask(mask_bin):
                # Это стандартная маска (например, 255.255.255.0 или 255.128.0.0)
                return (ip_bin & mask_bin) == (net_bin & mask_bin)
            else:
                # Это Wildcard (включая разрывные и экстремальные вроде 3.255.255.255)
                # Сравниваем через инверсию wildcard-маски: хосты совпадут там, где у вайлдкарда были нули
                return (ip_bin & ~mask_bin) == (net_bin & ~mask_bin)
        except Exception:
            return False
            
    return False


def prepare_address_string(addr_block, group_cache):
    """Превращает блок адреса в список готовых подсетей/IP (с раскрытием ОГ из кэша)."""
    addr_block = addr_block.strip()
    
    if addr_block in ('any', 'any4'):
        return ['0.0.0.0 0.0.0.0']
    if addr_block.startswith('host '):
        clean_ip = addr_block.replace('host', '', 1).strip()
        return [f"{clean_ip} 255.255.255.255"]
    if 'object-group' in addr_block or 'addrgroup' in addr_block:
        g_name = addr_block.split()[-1]
        group_items = group_cache.get(g_name, [])
        return [f"{item['ipaddr']} {item['netmask']}" for item in group_items]
        
    return [addr_block]

def find_match_pipeline(acl_lines, src, dst, dst_port, prot, group_cache):
    """
    Та самая воронка (Pipeline), отсекающая лишнее.
    """
    logger.info('Воронка find_match_pipeline запущена')
    
    for line in acl_lines:
        line_clean = line.strip()
        # if not line_clean or any(k in line_clean for k in ('remark', 'elements', 'Access')):
        #     continue

        # --- Этап 1: Фильтр экшена ---
        if 'permit' not in line_clean and 'deny' not in line_clean:
            continue
        if 'established' in line_clean:
            continue
        
        # --- Этап 2: Быстрый разбор структуры ---
        match = ACL_STRUCTURE_PATTERN.search(line_clean)
        if not match:
            continue
        data = match.groupdict()

        # --- Этап 3: Фильтр протокола ---
        is_service_group = data['proto'].startswith('object-group')
        if not is_service_group:
            if data['proto'] != 'ip' and data['proto'] != prot:
                continue

        # --- Этап 4: Фильтр портов назначения (РАННИЙ) ---
        # Избавляет от проверок IP, если порт заведомо не подошел
        if data['proto'] != 'ip':
            if any(op in line_clean for op in ['eq', 'range', 'gt', 'lt']):
                if not l1.check_port(line_clean, dst_port):
                    continue

        # --- Этап 5: Раскрытие адресов и валидация IP через LineSplit ---
        src_options = prepare_address_string(data['src'], group_cache)
        dst_options = prepare_address_string(data['dst'], group_cache)
        
        match_found = False
        for src_opt in src_options:
            for dst_opt in dst_options:
                # Генерируем "чистую" строку без host/any/object-group для l1.acl_addr
                # test_line = f"{data['action']} {data['proto']} {src_opt} {dst_opt}"
                try:
                    # Ваша стандартная логика проверки вхождения IP в подсеть
                    # acl_src, acl_dst = l1.acl_addr(test_line)
                    # if (addr(src) in acl_src) and (addr(dst) in acl_dst):
                    if ip_matches_rule(src, src_opt) and ip_matches_rule(dst, dst_opt):
                        match_found = True
                        break
                except Exception as e:
                    print(e)
                    raise
                    continue
            if match_found:
                break

        # --- Этап 6: Остановка на первом совпадении (First Match) ---
        if match_found:
            if data['action'] == 'permit':
                return line_clean
            else:
                # Попали под явный deny — пакет заблокирован, поиск прекращаем
                logger.info(f"Пакет заблокирован правилом: {line_clean}")
                return '99999 deny ip any any'

    # Конец аксесс-листа — неявный deny
    return '99999 deny ip any any'

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
                if 'permit' in line or 'deny' in line:
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