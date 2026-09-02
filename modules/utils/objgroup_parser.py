import re
import ipaddress

cisco_output = '''Network object group BGP
 Description Upstream Provider Interfaces
 109.239.134.28 255.255.255.252
 217.67.185.56 255.255.255.252
 46.46.155.112 255.255.255.252
 46.46.155.116 255.255.255.252
 host 172.16.35.110
 '''

def objgroup_parse(cisco_output):
    objgroup_items = []
    # objgroup_item_counter = 1
    # objgroup_dict['items'] = {}
    
    
    for line in cisco_output.split('\n'):
        if 'description' in line.lower():
            continue
        else:
            line = line.replace('host', '255.255.255.255')
            raw_item = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            
            if len(raw_item) != 2:
                continue
            else:
                if raw_item[0] == '255.255.255.255':
                    objgroup_data = {
                        'ipaddr': raw_item[1],
                        'netmask': raw_item[0]
                    }
                else:
                    objgroup_data = {
                        'ipaddr': raw_item[0],
                        'netmask': raw_item[1]
                    }
                objgroup_items.append(objgroup_data)
    return objgroup_items

print(objgroup_parse(cisco_output))

parsed_objgroup = objgroup_parse(cisco_output)

for i in parsed_objgroup:
    for key, value in i.items():
        print(key, value)



            