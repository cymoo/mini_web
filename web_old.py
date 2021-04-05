"""
a minimum web framework
"""

from threading import RLock
from urllib.parse import unquote as url_unquote
import sys


class HTTPError(Exception):
    def __init__(self, code, msg=''):
        pass


def bad_request():
    return HTTPError(400)


def not_found():
    return HTTPError(404)


class cached_property:
    """
    A decorator that converts a function into a lazy property.
    The function is wrapped is called the first time to retrieve
    the result and then that calculated result is used the next time
    you access the value.
    The class has to have a '__dict__' in order for this property to work.

    It has a lock for thread safety.
    """
    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func
        self.lock = RLock()

    def __get__(self, obj, cls):
        if obj is None:
            return self
        with self.lock:
            value = obj.__dict__.get(self.__name__, None)
            if value is None:
                value = self.func(obj)
                obj.__dict__[self.__name__] = value
            return value

    def __set__(self, obj, value):
        obj.__dict__[self.__name__] = value


class Request:
    def __init__(self, environ):
        self.environ = environ

    @property
    def method(self):
        return self.environ.get('REQUEST_METHOD', 'GET').upper()

    @property
    def url(self):
        return ''

    @property
    def query_string(self):
        return self.environ.get('QUERY_STRING', '')

    @property
    def content_type(self):
        return self.environ.get('CONTENT_TYPE', '')

    @property
    def content_length(self):
        return int(self.environ.get('CONTENT_LENGTH') or -1)

    @cached_property
    def form(self):
        pass

    @property
    def host(self):
        """
        Returns the real host. First checks the 'X-Forwarded-Host' header, then the normal
        'Host' header, and finally the 'SERVER_NAME' environment variable.
        :return:
        """
        if 'HTTP_X_FORWARDED_HOST' in self.environ:
            rv = self.environ['HTTP_X_FORWARDED_HOST'].split(',', 1)[0].strip()
        elif 'HTTP_HOST' in self.environ:
            rv = self.environ['HTTP_HOST']
        else:
            rv = self.environ['SERVER_NAME']
            if (self.environ['wsgi.url_scheme'], self.environ['SERVER_PORT']) not \
                    in (('https', '443'), ('http', '80')):
                rv += ':' + self.environ['SERVER_PORT']
        return rv

    @property
    def client_addr(self):
        """
        Returns the effective client IP as a string.
        If the "HTTP_X_FORWARDED_FOR" header exists in the WSGI environ, the attribute
        returns the client IP address present in that header (e.g. if the header value
        is '192.168.1.1, 192.168.1.2', the value will be '192.168.1.1'). If no "HTTP_
        FORWARDED_FOR" header is present in the environ at all, this attribute will
        return the value of the "REMOTE_ADDR" header. if the "REMOTE_ADDR" header is
        unset, this attribute will return the value "0.0.0.0".
        """
        env = self.environ
        xff = env.get('HTTP_X_FORWARDED_FOR')
        if xff is not None:
            addr = xff.split(',')[0].strip()
        else:
            addr = env.get('REMOTE_ADDR', '0.0.0.0')
        return addr

    @property
    def path(self):
        """
        Requested path. This works a bit like the regular path info in
        the WSGI environment, but always include a leading slash, even if
        the URL root is accessed.
        :return:
        """
        return url_unquote(self.environ.get('PATH_INFO', ''))

    def get(self, name, default=None):
        """
        Return the environ item.
        """
        return self.environ.get(name, default)

    @property
    def is_xhr(self):
        requested_with = self.environ.get('HTTP_X_REQUESTED_WITH', '')
        return requested_with.lower() == 'xmlhttprequest'

    def __iter__(self):
        return iter(self.environ)

    def __len__(self):
        return len(self.environ)

    def __repr__(self):
        return '<%s: %s %s>' % (self.__class__.__name__, self.method, self.url)


class Response:
    def __init__(self, headers=None, status_code=200, content_type='text/html; charset=utf-8'):
        pass

    def get_header(self, name):
        pass

    def set_header(self, name, value):
        pass

    def remove_header(self, name):
        pass

    def __repr__(self):
        pass


class Router:
    pass


class MiniWeb:
    def __init__(self):
        pass

    def get(self, path):
        pass

    def post(self, path):
        pass

    def put(self, path):
        pass

    def delete(self, path):
        pass

    def wsgi(self, environ, start_response):
        pass

    def __call__(self, environ, start_response):
        return self.wsgi(environ, start_response)

    def run(self, host='127.0.0.1', port=9000):
        from wsgiref.simple_server import make_server
        sys.stderr.write('Server is running...Hit Ctrl-C to quit.\n')
        sys.stderr.write('Listening on http://%s:%d/.\n'.format(host, port))
        server = make_server(host, port, self)
        server.serve_forever()
