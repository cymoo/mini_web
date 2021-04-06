"""A minimum web framework"""

import os
import json
import re
import sys
from typing import *
import cgi
from urllib.parse import unquote, parse_qs
from http.cookies import SimpleCookie
from io import BytesIO


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


class FileStorage:
    def __init__(
            self,
            stream: BytesIO,
            name: str,
            filename: str,
            headers: Optional[dict] = None
    ) -> None:
        self.stream = stream or BytesIO()
        self.name = name
        self.raw_filename = filename
        self.headers = headers or {}

    def secure_filename(self) -> str:
        pass

    def save(self, dst: str, buffer_size: int = 4096) -> None:
        pass


class HttpError(Exception):
    code = 500

    def __init__(self, description: str) -> None:
        super().__init__()
        self.headers = []
        self.status = '%d %s'.format(self.code, HTTP_STATUS_CODES[self.code])
        self.description = description

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
    def query_string(self) -> str:
        return self._environ.get('QUERY_STRING', '')

    @property
    def method(self) -> str:
        return self._environ['REQUEST_METHOD']

    @property
    def path(self) -> str:
        return unquote(self._environ.get('PATH_INFO', ''))

    @property
    def content_type(self) -> str:
        return self._environ.get('CONTENT_TYPE', '')

    @property
    def content_length(self) -> int:
        return int(self._environ.get('CONTENT_LENGTH') or -1)

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

    # noinspection PyPep8Naming
    @cached_property
    def GET(self) -> dict:
        return parse_qs(self.query_string)

    # noinspection PyPep8Naming
    @cached_property
    def POST(self) -> dict:
        fields = cgi.FieldStorage(
            fp=self._environ['wsgi.input'],
            environ=self._environ,
            keep_blank_values=True
        )
        fields = fields.list or []
        post = dict()

        for item in fields:
            if item.filename:
                post[item.name] = FileStorage(item.file, item.name, item.filename, item.headers)
            else:
                post[item.name] = item.value
        return post

    @cached_property
    def json(self) -> Optional[dict]:
        ctype = self.content_type.lower().split(';')[0]
        if ctype != 'application/json':
            return None

        body = self._get_raw_body()
        try:
            return json.loads(body)
        except (ValueError, TypeError):
            raise BadRequest('Invalid JSON')

    @cached_property
    def cookies(self) -> dict:
        http_cookie = self._environ.get('HTTP_COOKIE', '')
        return dict((cookie.key, unquote(cookie.value)) for cookie in SimpleCookie(http_cookie).values())

    def _get_raw_body(self) -> bytes:
        stream = self._environ['wsgi.input']
        bytes_length = max(0, self.content_length)
        return stream.read(bytes_length)

    def __iter__(self) -> Iterable:
        return iter(self._environ)

    def __len__(self) -> int:
        return len(self._environ)

    def __str__(self) -> str:
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
        return None

    @property
    def status(self):
        return None

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

    def error(self, code: int, callback=None):
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
