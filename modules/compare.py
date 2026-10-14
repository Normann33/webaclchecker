import logging
# Импортируем новую оптимизированную функцию-воронку вместо старой find_match
from modules.findmatch import find_match_pipeline

logger = logging.getLogger(__name__)

def compare(acl, src, dst, dst_port, prot, group_cache):
    logger.debug('compare started')
    
    # Избавляемся от неиспользуемой global переменной _acl для чистоты кода
    
    # Передаем строки ACL и кэш групп в воронку
    result = find_match_pipeline(acl, src, dst, dst_port, prot, group_cache)
    logger.debug(f'Matched line is: {result}')
    
    if 'permit' in result:
        return f'PASSED, {result}'
    elif 'deny' in result:
        return f'BLOCKED, {result}'
    else:
        return 'BLOCKED by implicit deny'

if __name__ == "__main__":
    # Для тестов (параметр group_cache по умолчанию пустой)
    compare(acl, src, dst, dst_port, prot, group_cache={})
