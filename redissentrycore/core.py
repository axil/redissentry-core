import logging, redis
import weakref

from .utils import fallback

from .filters import (
    Logger, FilterA, FilterB, FilterW, 
    FilterZA, FilterZB, FilterZW,
)

class RedisSentryBase(Logger):
    def __init__(self, ip, username, host, port, password, db, store_history_record):
        self.ip = ip
        self.username = username
        self.store_history_record = store_history_record
        self.db = db            # storing for debug purposes since there's no way to ask Redis which db it is using now

        self.r = redis.Redis(host=host, port=port, password=password, db=db)
        self.logger = logging.getLogger('redissentry')
        self.user_exists = None
    

class RedisSentry(RedisSentryBase):
    def __init__(self, ip, username, 
            host = 'localhost',
            port = 6379,
            password = '',
            db = 0,
            store_history_record = lambda *x, **y: None,
            user_exists_callback = lambda x: False):

        super(RedisSentry, self).__init__(ip, username, host, port, password, db, store_history_record)
        
        self.user_exists_callback = user_exists_callback
        
        kw = {'ip': ip, 'username': username, 'logger': self.logger, 'r': self.r, 'rs': weakref.ref(self)}
        self.fa = FilterA(**kw)
        self.fb = FilterB(**kw)
        self.fw = FilterW(**kw)
        self.fza = FilterZA(**kw)
        self.fzb = FilterZB(**kw)
        self.fzw = FilterZW(**kw)

    def cached_user_exists(self, username):
        if self.user_exists is None:
            self.user_exists = self.user_exists_callback(username)
        return self.user_exists
    
    def whitelist(self):
        self.fw.whitelist()
    
    def is_whitelisted(self):
        return self.fw.is_whitelisted()
    
    @fallback('')
    def ask(self):
        self.whitelisted = self.is_whitelisted()
        if self.whitelisted:
            res = self.fw.test()
        else:
            res = max(self.fa.test(), self.fb.test())
        return res[1]
    
    @fallback('')
    def inform(self, result):
        if result:
            self.whitelist()
            res = 0, ''
        else:
            if self.whitelisted:
                res = self.fw.update()
            else:
                res = max(self.fa.update(), self.fb.update())
        return res[1]


# Integration examples:

def protected_auth1():
    # user has to make another login attempt to get to know that he's blocked

    sentry = RedisSentry(ip, username)         ##
    msg = sentry.ask()
    if msg:
        raise Exception(msg)
    res = auth()                               ##
    sentry.inform(res)

def protected_auth2(error_msg):
    # user is informed that he's blocked right away

    sentry = RedisSentry(ip, username)         ##
    msg = sentry.ask()
    if msg:
        raise Exception(msg)
    res = auth()                               ##
    msg = sentry.inform(res)
    if msg:
        raise Exception(error_msg + ' ' + msg)


