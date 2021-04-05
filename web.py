"""A minimum web framework"""

import sys
from typing import *
import cgi
from urllib.parse import unquote, parse_qs
from http.cookies import SimpleCookie


HTTP_STATUS_CODES = {
    200: 'OK',
    301: 'Moved Permanently',
    303: 'See Other',
    400: 'Bad Request',
    404: 'Not Found',
    500: 'Internal Server Error',
}


# noinspection PyPep8Naming
class cached_property:
    def __init__(self, func):
        self.__name__ = func.__name__
        self.__module__ = func.__module__
        self.__doc__ = func.__doc__

        self.func = func

    def __get__(self, obj, cls):
        if obj is None:
            return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


class HttpError(Exception):
    code = 500

    def __init__(self) -> None:
        super().__init__()
        self.headers = []
        self.status = '%d %s'.format(self.code, HTTP_STATUS_CODES[self.code])

    def set_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def __str__(self) -> str:
        return self.status


class BadRequest(HttpError):
    code = 400


class NotFound(HttpError):
    code = 404


class InternalServerError(HttpError):
    code = 500


class Request:
    def __init__(self, environ: dict) -> None:
        self._environ = environ

    @property
    def query_string(self, parse=True) -> Union[str, dict]:
        value = self._environ.get('QUERY_STRING', '')
        if parse:
            value = parse_qs(value)
        return value

    @property
    def method(self) -> str:
        return self._environ['REQUEST_METHOD']

    @property
    def path(self) -> str:
        return unquote(self._environ.get('PATH_INFO', ''))

    @property
    def content_type(self):
        return self._environ.get('CONTENT_TYPE', '')

    @property
    def content_length(self) -> int:
        return int(self._environ.get('CONTENT_LENGTH') or -1)

    @cached_property
    def cookies(self) -> dict:
        http_cookie = self._environ.get('HTTP_COOKIE', '')
        return dict((cookie.key, unquote(cookie.value)) for cookie in SimpleCookie(http_cookie).values())

    @property
    def host(self) -> str:
        return self._environ.get('HTTP_HOST', '')

    @property
    def remote_addr(self) -> str:
        env = self._environ
        xff = env.get('HTTP_X_FORWARDED_FOR')

        if xff is not None:
            addr = xff.split(',')[0].strip()
        else:
            addr = env.get('REMOTE_ADDR', '0.0.0.0')
        return addr

    @cached_property
    def headers(self) -> dict:
        rv = {}

        for key, value in self._environ.items():
            # convert 'HTTP_XXX' to 'XXX'
            if key.startswith('HTTP_'):
                name = key[5:].replace('_', '-').upper()
                rv[name] = value

        return rv

    def get_header(self, name: str) -> str:
        return self.headers.get(name.upper(), '')

    @cached_property
    def inputs(self):
        def _convert(item):
            return item
        # if isinstance(item, list):
            #     return [_to_unicode(i.value) for i in item]
            # if item.filename:
            #     return MultipartFile(item)
            # return _to_unicode(item.value)

        fs = cgi.FieldStorage(
            fp=self._environ['wsgi.input'],
            environ=self._environ,
            keep_blank_values=True
        )
        inputs = dict()
        for key in fs:
            inputs[key] = _convert(fs[key])
        return inputs

    def get_raw_data(self):
        fp = self._environ['wsgi.input']
        return fp.read()

    @property
    def form(self):
        pass

    @property
    def files(self):
        pass

    @property
    def json(self):
        pass

    def __iter__(self):
        return iter(self._environ)

    def __len__(self):
        return len(self._environ)

    def __str__(self):
        return '<%s: %s %s>' % (self.__class__.__name__, self.method, self.path)


class BaseResponse:
    def __init__(self, headers=None, status_code=200, content_type='text/html; charset=utf-8'):
        pass

    def get_header(self, name):
        pass

    def set_header(self, name, value):
        pass

    def unset_header(self, name):
        pass

    @property
    def headers(self):
        pass

    @property
    def status(self):
        pass

    @status.setter
    def status(self, value):
        pass

    def set_cookie(
            self,
            name,
            value,
            max_age=None,
            expires=None,
            path='/',
            domain=None,
            secure=False,
            http_only=True
    ):
        pass

    def unset_cookie(self, name):
        pass

    def __str__(self):
        pass


class HttpResponse(BaseResponse):
    pass


class JsonResponse(BaseResponse):
    pass


class FileResponse(BaseResponse):
    pass


class Redirect(BaseResponse):
    pass


class Router:
    def __init__(self):
        pass

    def add(self, path, method, callback):
        pass

    def match(self, path, method):
        pass

    def __str__(self):
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

    def __str__(self):
        pass
