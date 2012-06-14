===========
RedisSentry
===========

This is generic RedisSentry documentaion, for django specific notes,
see django-redissentry docs.

Installation
------------

This is how RedisSentry can be integrated into any python-powered project (eg Flask):

::

    from redissentry import RedisSentry
    
    def protected_auth(username, password):
        sentry = RedisSentry(ip, username)
        msg = sentry.ask()
        if msg:
            raise Exception(msg)
        res = auth(username, password)
        msg = sentry.inform(bool(res))
        if not res:
            raise Exception('Incorrect username or password. ' + msg)
        return res

where auth() is the original auth function.

