"""A minimum web framework"""

import cgi
import json
import os
import re
import sys
from datetime import datetime, date, tzinfo
from http.client import responses
from http.cookies import SimpleCookie
from io import BytesIO
from typing import *
from urllib.parse import unquote, parse_qs


HTTP_STATUS_LINES = {key: '%d %s' % (key, value) for key, value in responses.items()}


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


def hkey(key: str) -> str:
    if '\n' in key or '\r' in key or '\0' in key:
        raise ValueError('Header name must not contain control characters: %s'.format(key))
    return key.title().replace('_', '-')


def hval(value: str) -> str:
    if '\n' in value or '\r' in value or '\0' in value:
        raise ValueError('Header value must not contain control characters: %s'.format(value))
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

    @staticmethod
    def secure_filename(filename: str) -> str:
        filename = re.sub(r'[^\u4e00-\u9fa5\w\-.]+', '', filename).strip()
        filename = re.sub(r'[-\s]+', '-', filename).strip('.-')
        return filename[:255] or 'empty'

    def save(self, dst: str, overwrite=False) -> None:
        if not os.path.isdir(dst):
            raise HttpError(500, 'Folder does not exists: %s'.format(dst))

        filepath = os.path.join(dst, self.secure_filename(self.raw_filename))
        if os.path.exists(filepath) and not overwrite:
            raise HttpError(500, 'File exists: %s.'.format(filepath))

        with open(filepath, 'wb') as fp:
            stream = self.stream
            while True:
                buf = stream.read(4096)
                if not buf:
                    break
                fp.write(buf)


class HttpError(Exception):
    code = 500

    def __init__(self, code: int, description: str) -> None:
        super().__init__()
        self.headers = []
        self.code = code
        # self.status = '%d %s'.format(self.code, HTTP_STATUS_CODES[self.code])
        self.description = description

    def set_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def __str__(self) -> str:
        # return self.status
        return ''


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
            raise HttpError(400, 'Invalid JSON')

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
    default_status_code = 200
    default_content_type = 'text/html; charset=UTF-8'

    def __init__(
            self,
            body: Optional[Any] = None,
            status_code: int = 200,
    ) -> None:
        self.body = body
        self.status_code = status_code or self.default_status_code
        self._cookies = SimpleCookie()
        self._headers = {}

    def get_header(self, name: str) -> str:
        return self._headers.get(hkey(name), [''])(-1)

    def set_header(self, name: str, value: str) -> None:
        self._headers[hkey(name)] = [hval(value)]

    def add_header(self, name: str, value: str) -> None:
        self._headers.setdefault(hkey(name), []).append(hval(value))

    def unset_header(self, name: str) -> None:
        del self._headers[hkey(name)]

    @property
    def headers(self) -> List[Tuple[str, str]]:
        """ WSGI conform list of (header, value) tuples. """
        headers = list(self._headers.items())

        if 'Content-Type' not in self._headers:
            headers.append(('Content-Type', [self.default_content_type]))

        headers = [(name, val) for (name, values) in headers for val in values]

        if self._cookies:
            for cookie in self._cookies.values():
                headers.append(('Set-Cookie', hval(cookie.OutputString())))

        # TODO: must convert to latin1?
        # headers = [(key, value.encode('utf8').decode('latin1')) for (key, value) in headers]
        return headers

    @property
    def status_line(self) -> str:
        return HTTP_STATUS_LINES.get(self.status_code, '%d Unknown' % self.status_code)

    def set_cookie(
            self,
            name: str,
            value: str,
            path: str = '/',
            secure: bool = False,
            httponly: bool = False,
            max_age: Optional[int] = None,
            expires: Optional[Union[str, datetime, int, float]] = None,
            domain: Optional[str] = None,
            same_site: Optional[str] = None,
    ) -> None:
        self._cookies[name] = value

        if path:
            self._cookies[name]['path'] = path
        if secure:
            self._cookies[name]['secure'] = secure
        if httponly:
            self._cookies[name]['httponly'] = httponly
        if domain:
            self._cookies[name]['domain'] = domain
        if max_age:
            self._cookies[name]['max-age'] = max_age
        if same_site:
            self._cookies[name]['samesite'] = same_site.lower()

        if expires:
            # TODO: deal with datetime in Python is too boring...
            self._cookies[name][expires] = expires

    def unset_cookie(self, name: str, **kw) -> None:
        kw['max_age'] = -1
        kw['expires'] = 0
        self.set_cookie(name, '', **kw)

    def __str__(self) -> str:
        rv = ''
        for name, value in self.headers:
            rv += '%s: %s\n'.format(name.title(), value.strip())
        return rv


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
