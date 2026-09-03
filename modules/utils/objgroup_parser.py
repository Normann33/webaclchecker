import re

cisco_output = ''

def objgroup_parse(cisco_output):
    objgroup_items = []
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


if __name__ == '__main__':
    print(objgroup_parse(cisco_output))





            