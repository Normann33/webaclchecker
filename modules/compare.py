import logging
from modules.normalise import normalise
from modules.findmatch import find_match

logger = logging.getLogger(__name__)

def compare(acl, src, dst, dst_port, prot):
    logger.debug('compare started')
    global _acl
    _acl = acl
    result = find_match(acl, src, dst, dst_port, prot)
    logger.debug(f'Matched line is: {result}')

    if 'permit' in result:
        return f'PASSED,  {result}'
    elif 'deny' in result:
        return f'BLOCKED,  {result}'
    else: 
        return 'BLOCKED by implicit deny'

if __name__ == "__main__":
    compare(acl, src, dst, dst_port, prot)