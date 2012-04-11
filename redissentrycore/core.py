import logging, redis
import weakref

from .utils import fallback

from .filters import (
    Logger, FilterA, FilterB, FilterW, 
    FilterZAImplicit, FilterZAExplicit,
    FilterZBImplicit, FilterZBExplicit,
    FilterZWImplicit, FilterZWExplicit,
)

class RedisSentryBase(Logger):
    def __init__(self, ip, username, store_history_record, db):
        self.ip = ip
        self.username = username
        self.store_history_record = store_history_record
        self.db = db            # storing for debug purposes since there's no way to ask Redis which db it is using now

        self.r = redis.Redis(db=db)
        self.logger = logging.getLogger('redissentry')
        self.user_exists = None
    

class FilterALite(FilterA):
    delays = 5, 10, 30, 60, 5*60

    def get_delay(self, n):
        N = self.period
        if n==0 or n % N != 0:
            return 0
        elif n//N < len(self.delays):
            return self.delays[n//N]
        else:
            return self.delays[-1]


class RedisSentryLite(RedisSentryBase):
    # Doesn't handle distributed attacks, less efficient, provides worse user experience.
    # Simple.

    def __init__(self, ip, username, db=0, store_history_record = lambda *x, **y: None):
        super(RedisSentryLite, self).__init__(ip, username, db, store_history_record)
        self.fa = FilterALite(ip, username)
    
    def ask(self):
        return self.fa.test()[-1]

    def inform(self, result):
        return self.fa.update()[-1]


class RedisSentry(RedisSentryBase):
    # Recommended class:
    # Handles distributed attacks, has whitelist,
    # minimizes blocking time as experienced by ordinary user while
    # maximizing blocking time as experienced by attacker

    def __init__(self, ip, username, 
            user_exists_callback = lambda x: False,
            store_history_record = lambda *x, **y: None,
            db = 0):

        super(RedisSentry, self).__init__(ip, username, store_history_record, db)
        
        self.user_exists_callback = user_exists_callback
        
        kw = {'ip': ip, 'username': username, 'logger': self.logger, 'r': self.r, 'rs': weakref.ref(self)}
        self.fa = FilterA(**kw)
        self.fb = FilterB(**kw)
        self.fw = FilterW(**kw)
        self.fzae, self.fzai = FilterZAExplicit(**kw), FilterZAImplicit(**kw)
        self.fzbe, self.fzbi = FilterZBExplicit(**kw), FilterZBImplicit(**kw)
        self.fzwe, self.fzwi = FilterZWExplicit(**kw), FilterZWImplicit(**kw)

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


