import re
import ipaddress
from modules.portreplace import port_replace

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network

class LineSplit:
# Разбираем строку из аксесс-листа

    def convert_to_cidr(self, ip, mask):
        # Преобразуем маску в CIDR
        network = ipaddress.ip_network(f'{ip}/{mask}', strict=False)
        return str(network)

    def acl_addr(self, line):
        global _line
        _line = line
        z = ''
        acl_src = ''
        acl_dst = ''
        port_line = ''
        ip_mask_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})')
        ip_addresses = ip_mask_pattern.findall(_line)
        results = []
        for match in ip_addresses:
            if match[0] and match[1]:
                try:
                    cidr = self.convert_to_cidr(match[0], match[1])
                    results.append(cidr)
                except:
                    results.append(f'{match[0]}/{match[1]}')
                    print('DEBUG convert_to_cidr: Не могу разобрать строку', line)      
            elif match[2]:  # Формат CIDR
                results.append(match[2])
        try:
            acl_src = net(results[0])
            acl_dst = net(results[1])
        except:
            acl_src = results[0]
            acl_dst = results[1]
            # print("DEBUG acl_addr: Не могу разобрать строку", line)
            # pass
        return acl_src, acl_dst
    
    def check_port(self, line, port_to_check):
            try:
                port_to_check = int(port_replace(str(port_to_check)))
            except (ValueError, TypeError):
                return False
    
            words = line.split()
            for i, word in enumerate(words):
                if i == 0:
                    continue
                prev = words[i - 1].lower()
    
                # --- eq: один или несколько портов через запятую/пробел ---
                if prev == 'eq':
                    for part in re.split(r'[\s,]+', word):
                        if not part:
                            continue
                        try:
                            if int(port_replace(part)) == port_to_check:
                                return True
                        except (ValueError, TypeError):
                            continue
    
                # --- neq: подходит, если порт НЕ совпал ни с одним из списка ---
                elif prev == 'neq':
                    neq_ports = []
                    for part in re.split(r'[\s,]+', word):
                        if not part:
                            continue
                        try:
                            neq_ports.append(int(port_replace(part)))
                        except (ValueError, TypeError):
                            continue
                    if neq_ports and port_to_check not in neq_ports:
                        return True
    
                # --- lt / gt: один токен ---
                elif prev in ('lt', 'gt'):
                    try:
                        port = int(port_replace(word))
                    except (ValueError, TypeError):
                        continue
                    if prev == 'lt' and port_to_check < port:
                        return True
                    if prev == 'gt' and port_to_check > port:
                        return True
    
                # --- range: два токена ---
                elif prev == 'range' and i + 1 < len(words):
                    try:
                        start = int(port_replace(word))
                        end = int(port_replace(words[i + 1]))
                    except (ValueError, TypeError):
                        continue
                    if start <= port_to_check <= end:
                        return True
    
            return False

    

if __name__ == '__main__':
    line_split()