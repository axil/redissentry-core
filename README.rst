===========
RedisSentry
===========

This is generic RedisSentry documentaion, to see django-specific notes,
redissentry.django docs.

Installation
------------

    from redissentry import RedisSentry
    
    def protected_auth(username, password):
        sentry = RedisSentry(ip, username)
        msg = sentry.ask()
        if msg:
            raise Exception(msg)
        res = auth(username, password)
        msg = sentry.inform(bool(res))
        if not res:
            raise Exception('Incorrect username or password.' +  ' ' + msg)
        return res

where auth() is a standard auth function.

