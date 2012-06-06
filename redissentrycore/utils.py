from math import log, exp
from random import random
from functools import wraps
from traceback import format_exc

def humanize(t):
    """
    >>> print humanize(0)
    now
    >>> print humanize(1)
    in a minute
    >>> print humanize(60)
    in a minute
    >>> print humanize(61)
    in 2 minutes
    >>> print humanize(3600)
    in an hour
    >>> print humanize(3601)
    in 2 hours
    """
    m, s = divmod(t, 60)
    if s:
        m += 1                 # ceil minutes 
    h, m = divmod(m, 60)
    if m and h:
        h += 1                 # ceil hours
#    d, h = divmod(h, 24)

    if h > 1:
        res = 'in %d hours' % h
    elif h == 1:
        res = 'in an hour'
    else:
        if m > 1:
            res = 'in %d minutes' % m
        elif m == 1:
            res = 'in a minute'
        else:
            res = 'now'
    return res

def fallback(*rargs):
    def factory(f):
        @wraps(f)
        def wrapper(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except:
#                print format_exc()
                self.error(format_exc())
                return rargs[0] if len(rargs)==1 else rargs
        return wrapper
    return factory

def test_fallback():
    @fallback(0, '')
    def foo(self, x):
        1/0
    
    z = foo(1, 2)
    print 'z = ' + `z`

if __name__ == "__main__":
#    import doctest
#    doctest.testmod()
    test_exprand()
#    test_exprand1()
#    test_fallback()
    pass
