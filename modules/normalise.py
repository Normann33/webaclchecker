import re

def parse_running_config(config_text):
    """
    Универсальный парсер конфигураций Cisco (IOS, XE, XR, NX-OS, ASA) и Arista EOS.
    Основан на анализе контекста отступов (Иерархический парсинг).
    """
    parsed = {
        "acls": {},
        "object_groups": {},
        "interfaces": {}
    }
    
    if not config_text:
        return parsed

    # Регулярные выражения для определения типов глобальных секций (без отступов)
    # Ищет любое упоминание access-list/access-group/filter в начале строки
    ANY_ACL_START = re.compile(r'^(?:ip|ipv6)?\s*access-list\s+(?:extended|standard|matrix)?\s*(\S+)', re.IGNORECASE)
    # Теперь регулярка ловит и 'object-group network NAME', и 'addrgroup NAME'
    ANY_OG_START = re.compile(r'^(?:object-group|addrgroup)\s+(?:network|address|service)?\s*(\S+)', re.IGNORECASE)
    
    SERVICE_PORT_PATTERN = re.compile(
    r'^(?:port-object|protocol-object)?\s*(?P<proto>tcp|udp|ip)?\s*'
    r'(?P<op>eq|range|gt|lt|neq)\s+(?P<val>[\w\s-]+?)\s*$',
    re.IGNORECASE
    )

    ANY_IFACE_START = re.compile(r'^interface\s+(\S+)', re.IGNORECASE)

    # Вспомогательные регулярки для внутренностей object-group
    HOST_PATTERN = re.compile(r'host\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
    SUBNET_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)

    current_context = None  # Может быть: 'acl', 'og', 'iface'
    current_name = None     # Имя текущей секции

    for line in config_text.splitlines():
        line_strip = line.strip()
        
        # Пропускаем пустые строки, комментарии и баннеры
        if not line_strip or line_strip.startswith('!') or line_strip.startswith('#'):
            continue

        # Проверяем, имеет ли строка отступ (признак подсекции)
        has_indent = line.startswith(' ') or line.startswith('\t')

        if not has_indent:
            # === МЫ НА ГЛОБАЛЬНОМ УРОВНЕ (НЕТ ОТСТУПА) ===
            current_context = None
            current_name = None

            # 1. Проверяем старые плоские нумерованные списки (Cisco IOS: access-list 101 permit...)
            if line_strip.startswith('access-list '):
                parts = line_strip.split()
                if len(parts) > 2 and parts[1].isdigit():
                    acl_name = parts[1]
                    if acl_name not in parsed["acls"]:
                        parsed["acls"][acl_name] = []
                    parsed["acls"][acl_name].append(line_strip)
                continue

            # 2. Проверяем начало блочного именованного ACL (Cisco/Arista)
            match_acl = ANY_ACL_START.match(line_strip)
            if match_acl:
                current_name = match_acl.group(1)
                current_context = 'acl'
                if current_name not in parsed["acls"]:
                    parsed["acls"][current_name] = []
                continue

            # 3. Проверяем начало Object-Group (Cisco/Arista)
            match_og = ANY_OG_START.match(line_strip)
            if match_og:
                current_name = match_og.group(1)
                current_context = 'og'
                if current_name not in parsed["object_groups"]:
                    parsed["object_groups"][current_name] = []
                continue

            # 4. Проверяем начало интерфейса
            match_iface = ANY_IFACE_START.match(line_strip)
            if match_iface:
                # Извлекаем полное имя интерфейса, например Ethernet1/1 или GigabitEthernet0/0/1
                current_name = line_strip.split()[-1]
                current_context = 'iface'
                if current_name not in parsed["interfaces"]:
                    parsed["interfaces"][current_name] = {"in": "noacl", "out": "noacl", 'ip': None}
                continue

        else:
            # === МЫ ВНУТРИ БЛОКА (ЕСТЬ ОТСТУП) ===
            if not current_context or not current_name:
                continue

            # А. Контекст сбора строк ACL
            if current_context == 'acl':
                # Для воронки важно, чтобы строка содержала permit/deny.
                # Если в NX-OS/Arista строки нумеруются (10 permit tcp...), сохраняем как есть
                parsed["acls"][current_name].append(line_strip)

            # Б. Контекст сбора элементов Object-Group
            elif current_context == 'og':
                # Извлекаем IP-адреса универсально, независимо от префиксов (network-object/host/subnet)
                m_service = SERVICE_PORT_PATTERN.search(line_strip)
                if m_service:
                    s_data = m_service.groupdict()
                    # Если протокол опущен (бывает на ASA внутри object-group service tcp), 
                    # то по умолчанию берем 'ip' или можно будет наследовать его позже
                    proto = s_data['proto'].lower() if s_data['proto'] else 'ip'
                    
                    parsed["object_groups"][current_name].append({
                        "protocol": proto,
                        "port_op": s_data['op'].lower(),
                        "port_val": s_data['val'].strip()
                    })
                    continue
                m_host = HOST_PATTERN.search(line_strip)
                if m_host:
                    parsed["object_groups"][current_name].append(
                        {"ipaddr": m_host.group(1), "netmask": "255.255.255.255"}
                    )
                    continue
                    
                m_sub = SUBNET_PATTERN.search(line_strip)
                if m_sub:
                    # Будь то "network-object 10.1.1.0 255.255.255.0" или просто "10.1.1.0 255.255.255.0"
                    parsed["object_groups"][current_name].append(
                        {"ipaddr": m_sub.group(1), "netmask": m_sub.group(2)}
                    )

            # В. Контекст сбора параметров интерфейса (Поиск привязки ACL)
            elif current_context == 'iface':
                # Ищем команды: ip access-group NAME in, ip access-group NAME out, ip access-group NAME input (Arista)
                # или ip access-list input/output (Arista EOS)
                if 'access-group' in line_strip or 'access-list' in line_strip:
                    parts = line_strip.split()
                    
                    # Определяем направление (обычно последнее или предпоследнее слово: in/out/input/output)
                    direction = None
                    if any(x in parts for x in ['in', 'input', 'ingress']):
                        direction = 'in'
                    elif any(x in parts for x in ['out', 'output', 'egress']):
                        direction = 'out'
                        
                    if direction:
                        # Имя ACL — это то слово, которое идет перед направлением или после команды
                        # Универсальный хак: исключаем служебные слова, берем то, что похоже на имя
                        for part in parts:
                            if part.lower() not in ['ip', 'ipv6', 'access-group', 'access-list', 'in', 'out', 'input', 'output', 'ingress', 'egress']:
                                parsed["interfaces"][current_name][direction] = part
                                break
                if line_strip.lower().startswith('ip address '):
                    # Разделяем строку по пробелам на элементы
                    parts = line_strip.split()
                    
                    # Проверяем, что в строке достаточно элементов (минимум: ip address IP)
                    if len(parts) >= 3:
                        potential_ip = parts[2]
                        
                        # Убираем CIDR-маску, если IP указан в формате X.X.X.X/YY
                        if '/' in potential_ip:
                            potential_ip = potential_ip.split('/')[0]
                            
                        # Записываем найденный IP в наш интерфейс
                        parsed["interfaces"][current_name]["ip"] = potential_ip

    return parsed
