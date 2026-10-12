import re
from modules.hostreplace import host_replace
from modules.objgroupreplace import obj_group_replace
from modules.utils.objgroup_parser import objgroup_parse

OBJ_GROUP_PATTERN = re.compile(r'(?:object-group|addrgroup)\s+(\S+)', re.IGNORECASE)

def normalise(acl, ssh_connect):
    '''Приведение ip адресов в строках к единому виду'''
    acl_clean = []
    
    # Кэш для object-groups в рамках ОДНОГО вызова функции normalise.
    # Предотвращает повторные SSH-запросы для одинаковых групп.
    fetched_groups = {}

    for line in acl:
        if any(k in line for k in ('remark', 'Extended IP access', 'Access', 'elements')):
            continue
        if 'access-list' in line:
            line = ' '.join(line.split()[3::])
        if 'host' in line:
            line = host_replace(line)
        line = line.replace('host', '255.255.255.255').replace('any4', '0.0.0.0 0.0.0.0').replace('any', '0.0.0.0 0.0.0.0')
        if 'object-group' in line or 'addrgroup' in line:
            # obj_group_finder = re.finditer(r'object-group (\S+)|addrgroup (\S+)', line)
            obj_group_names = OBJ_GROUP_PATTERN.findall(line)
            # for i in obj_group_finder:
            #     obj_group_names.append(i.group(1))
            obj_groups = {}
            for i in obj_group_names:
                objgroup_items_raw = ssh_connect.send_command(f'show object-group {i}')
                if 'invalid' in objgroup_items_raw.lower():
                    objgroup_items_raw = ssh_connect.send_command(f'show object-group name {i}')
                objgroup_items = objgroup_parse(objgroup_items_raw)
                obj_groups[i] = objgroup_items
            temp_acl = []
            if len(obj_group_names) == 1:
                for item in objgroup_items:
                    acl_clean.append(obj_group_replace(line, obj_group_names[0], ''.join(f"{item['ipaddr']} {item['netmask']}")).replace('object-group', ''))
            else:
                for item in objgroup_items:
                    temp_acl.append(obj_group_replace(line, obj_group_names[0], ''.join(f"{item['ipaddr']} {item['netmask']}")).replace('object-group', ''))
                for i in temp_acl:
                    for item in objgroup_items:
                        acl_clean.append(obj_group_replace(i, obj_group_names[1], ''.join(f"{item['ipaddr']} {item['netmask']}")).replace('object-group', ''))
        else:
            acl_clean.append(line.strip('\n'))
    return acl_clean

if __name__ == '__main__':
    normalise(acl)