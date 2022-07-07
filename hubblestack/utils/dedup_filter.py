from collections import deque
import time


class DedupFilter:

    def __init__(self, maxlen = 0, expire_seconds = 24*60*60, on_expire = None):
        self.maxlen = maxlen
        self.cache = deque(maxlen = self.maxlen)
        self.expire_seconds = expire_seconds

    """
    cache structure:
       data is a key
       value is time
    """
    
    def _expire(self):
        now = time.time()
        expired = True
        while expired:
            expired = False
            for i in self.cache:
                if (now - i['time']) > self.expire_seconds:
                    # remove from cache
                    self.cache.remove(i)
                    expired = True
                    break


    def find(self, data):
        for i in self.cache:
            if i['data'] == data:
                return i
        return None

    def refresh(self, data):
        value = self.find(data)
        if value != None:
            self.cache.remove(value)
            return self._add(value['data'])
        else:
            return None

    def _add(self, data):
        value = {'time': time.time(), 'data': data}
        self.cache.append(value)
        return value


    def filter(self, data):
        """
        data is a string
        drop all items from cache that are 23 hours old or older
        if in cache, drop from data
        if in cache, but not in data, drop from cache
        if not in cache, but in data, add to cache, and return
        if not in cache, return false
        if in cache, return true
        """
        self._expire()
        cached_value = self.refresh(data)
        if cached_value == None:
            self._add(data)
            return False
        return True

