from traceback import format_exc
from datetime import timedelta as td
from struct import pack, unpack

from .utils import exprand, humanize, fallback

def sign(x):
    if x>0:
        return 1
    elif x<0:
        return -1
    else:
        return 0

class Logger(object):
    def log(self, msg):
        self.logger.info('%-15s %-24s ' % (self.ip, self.username[:21]) + msg)
    
    def debug(self, msg):
        self.logger.debug('%-15s %-24s ' % (self.ip, self.username[:21]) + msg)

    def error(self, msg):
        self.logger.error('%-15s %-24s ' % (self.ip, self.username[:21]) + msg)

class Filter(Logger):
    period = 5                          # triggers a block every 5 failed attempts
    delays = 5, 10, 30, 60              # minutes
    delta_counter_ttl = 24*60//5        # 5 failed attempts a day are allowed
    max_counter_ttl = 7*24*60           # a week
    error_message = 'Too many failed attempts. Try again %s.'

    def __init__(self, **kwargs):    # ip, username, logger, r, rs
        for k, v in kwargs.items():
            setattr(self, k, v)

    def get_delay(self, n):
        N = self.period
        assert type(n) == type(N) == int, 'both n and N are assumed to be int'
        if n==0 or n % N != 0:
            return 0
        elif n//N <= len(self.delays):
            return self.delays[n//N-1]
        else:
            return -exprand(3*60, 23*60)

    def get_counter_ttl(self, n):
        return min( n * self.delta_counter_ttl, self.max_counter_ttl )

    def test(self):
        try:
            r = self.r
            t = r.ttl(self.block)
            if t:
                b = int(r.get(self.block))
                self.log(self.log_message + ', ' +
                        ('%s' if b > 0 else '(%s)') % str(td(seconds=t)) + ' left')
                return t, b>0, self.error_message % (humanize(t) if b>0 else 'later')
            else:
                return t, 1, ''
        except:
            self.error(format_exc())


class FilterA(Filter):
    log_message = 'auth rejected from ip'
    
    def __init__(self, **kwargs):
        super(FilterA, self).__init__(**kwargs)
        self.counter = 'Ac:' + self.ip
        self.block   = 'Ab:' + self.ip

    def test(self):
        t, explicit, msg = super(FilterA, self).test()
        if t:
            if explicit:
                zt, zmsg = self.rs().fzae.update()
            else:
                zt, zmsg = self.rs().fzai.update()
        else:
            zt, zmsg = 0, ''
        return zt or t, zmsg or msg

    @fallback(0, '')
    def update(self):
        r = self.r
        n = r.incr(self.counter)
        log_msg = 'fa #%d from regular ip' % n
        t = self.get_delay(n) * 60
        if t:
            r.set(self.block, abs(int(r.get(self.block) or 1)) * sign(t))
            r.expire(self.block, abs(t))
            self.rs().store_history_record('ip', self.ip, self.username, n)
            log_msg += ', ip blocked for ' + ('%d' if t>0 else '(%d)') % abs(t/60) + ' min'
            res = abs(t), self.error_message % (humanize(t) if t>0 else 'later')
        else:
            res = 0, ''
        r.expire(self.counter, self.get_counter_ttl(n) * 60 + abs(t))
        self.log(log_msg + '; ttl = ' + str(td(minutes=self.get_counter_ttl(n))))
        return res


class FilterB(Filter):
    log_message = 'auth rejected for username'

    def __init__(self, **kwargs):
        super(FilterB, self).__init__(**kwargs)
        self.counter = 'Bc:' + self.username
        self.block   = 'Bb:' + self.username
        self.error_message = 'Too many failed attempts for %s. Try again %%s.' % self.username
    
    def test(self):
        t, explicit, msg = super(FilterB, self).test()
        if t:
            if explicit:
                zt, zmsg = self.rs().fzbe.update()
            else:
                zt, zmsg = self.rs().fzbi.update()
        else:
            zt, zmsg = 0, ''
        return zt or t, zmsg or msg

    @fallback(0, '')
    def update(self):
        res = 0, ''
        r = self.r
        ip_num = r.zcard(self.counter)
        if ip_num or self.rs().cached_user_exists(self.username):
            packed_ip = pack('4B', *map(int, self.ip.split('.'))) if self.ip else '\x00'*4
            i = r.zincrby(self.counter, packed_ip, 1)
            if i==1:
                ip_num += 1
            # fa_num = r.eval('s=0; for i,v in ipairs(KEYS[1]) do s=s+v end; return s', self.counter)    # for currently unstable version of redis (>= 2.6)
            stats = r.zrange(self.counter, 0, -1, withscores=1)
            fa_num = sum(int(v) for k, v in stats)
            if ip_num > 1:
                log_msg = 'fa #%d from ip #%d with the same username' % (fa_num, ip_num)
                t = self.get_delay(fa_num) * 60
                if t:
                    r.set(self.block, abs(int(r.get(self.block) or 1)) * sign(t))
                    r.expire(self.block, abs(t))
                    self.rs().store_history_record('username', ', '.join('%s(%.0f)' % ('.'.join(map(str,unpack('4B', k))), v) for k, v in stats)[:2048], self.username, ip_num)
                    log_msg += ', username blocked for ' + ('%d' if t>0 else '(%d)') % abs(t/60) + ' min'
                    res = abs(t), self.error_message % (humanize(t) if t>0 else 'later')
                self.log(log_msg)
            else:
                t = 0
            r.expire(self.counter, self.get_counter_ttl(fa_num) * 60 + abs(t))
        else:
            pass
        return res


class FilterW(Filter):
    counter_ttl = 30*24*60      # a month
    log_message = 'auth rejected for whitelisted ip:username'

    def __init__(self, **kwargs):
        super(FilterW, self).__init__(**kwargs)
        self.counter = 'Wc:' + self.ip + ':' + self.username
        self.block   = 'Wb:' + self.ip + ':' + self.username

    def whitelist(self):
        try:
            self.r.set(self.counter, 0)
            self.r.expire(self.counter, self.counter_ttl * 60)
            self.log('user whitelisted')
        except:
            self.logger.error(format_exc())
    
    def is_whitelisted(self):
        try:
            return self.r.get(self.counter) is not None
        except:
            self.logger.error(format_exc())

    def test(self):
        t, explicit, msg = super(FilterW, self).test()
        if t:
            if explicit:
                zt, zmsg = self.rs().fzwe.update()
            else:
                zt, zmsg = self.rs().fzwi.update()
        else:
            zt, zmsg = 0, ''
        return zt or t, zmsg or msg

    @fallback(0, '')
    def update(self):
        r = self.r
        n = r.incr(self.counter)
        r.expire(self.counter, self.counter_ttl * 60)
        log_msg = 'fa #%d from whitelisted ip:username' % n
        t = self.get_delay(n) * 60
        if t:
            r.set(self.block, abs(int(r.get(self.block) or 1)) * sign(t))
            r.expire(self.block, abs(t))
            self.rs().store_history_record('ip:username', self.ip, self.username, n)
            log_msg += ', blocked for ' + ('%d' if t>0 else '(%d)') % abs(t/60) + ' min'
            msg = self.error_message % (humanize(t) if t>0 else 'later')
        else:
            msg = ''
        self.log(log_msg)
        return t, msg
    

class FilterZ(Filter):
    block_type = ''

    @fallback(0, '')
    def update(self):
        r = self.r
        n = abs(r.incr(self.block) if int(r.get(self.block) or 1) > 0 else r.decr(self.block)) - 1
        log_msg = 'fa #%d from blocked %s' % (n, self.block_type)
        t = self.get_delay(n) * 60
        msg = ''
        if t:
            log_msg += ', suggested delay: ' + str(td(seconds=abs(t)))
            if abs(t) > r.ttl(self.block):
                r.set(self.block, abs(int(r.get(self.block) or 1)) * sign(t))
                r.expire(self.block, abs(t))
                self.rs().store_history_record(self.block_type, self.ip, self.username, blocked_attempts = n)
                log_msg += ', ' + self.block_type + ' blocked for ' + ('%s' if t>0 else '(%s)') % str(td(seconds=abs(t)))
                msg = self.error_message % (humanize(t) if t>0 else 'later')
        self.log(log_msg)
        return t, msg

class FilterZA(FilterZ):
    block_type = 'ip'

    def __init__(self, **kwargs):
        super(FilterZA, self).__init__(**kwargs)
        self.block   = 'Ab:' + self.ip

class FilterZB(FilterZ):
    block_type = 'username'

    def __init__(self, **kwargs):
        super(FilterZB, self).__init__(**kwargs)
        self.block   = 'Bb:' + self.username
        self.error_message = 'Too many failed attempts for %s. Try again %%s.' % self.username

class FilterZW(FilterZ):
    block_type = 'ip:username'

    def __init__(self, **kwargs):
        super(FilterZW, self).__init__(**kwargs)
        self.block   = 'Wb:' + self.ip + ':' + self.username

class FilterZExplicit(object):
    period = 9

    def get_delay(self, n):
        if n % self.period:
            return 0
        elif n == self.period:
            return 30
        else:
            return -exprand(3*60, 23*60)

class FilterZImplicit(object):
    period = 3

    def get_delay(self, n):
        if n % self.period:
            return 0
        else:
            return -exprand(3*60, 23*60)

class FilterZAExplicit(FilterZExplicit, FilterZA):  pass
class FilterZAImplicit(FilterZImplicit, FilterZA):  pass

class FilterZBExplicit(FilterZExplicit, FilterZB):  pass
class FilterZBImplicit(FilterZImplicit, FilterZB):  pass

class FilterZWExplicit(FilterZExplicit, FilterZW):  pass
class FilterZWImplicit(FilterZImplicit, FilterZW):  pass

