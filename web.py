"""A minimum web framework"""

import cgi
import hashlib
import json
import logging
import mimetypes
import os
import re
import sys
from http.client import responses
from http.cookies import SimpleCookie
from io import BytesIO
from typing import *
from tempfile import TemporaryFile
from urllib.parse import unquote, parse_qs, quote


# Helper functions
def tr(key: str) -> str:
    """Normalize HTTP Response header name"""
    return key.title().replace('_', '-')


def squeeze(value: List[str]) -> Union[str, List[str]]:
    if len(value) == 1:
        return value[0]
    else:
        return value


# noinspection PyPep8Naming
class cached_property:
    """
    A decorator that converts a function into a lazy property.
    The function wrapped is called the first time to retrieve the result
    and then that calculated result is cached.
    """

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


class FileWrapper:
    """Wrapper to convert file-like objects to iterables"""

    # stream: IO[bytes], NameError: name 'IO' is not defined?
    def __init__(self, stream, buffer_size: int = 8192):
        self.stream = stream
        self.buffer_size = buffer_size
        if hasattr(stream, 'close'):
            self.close = stream.close

    def __iter__(self) -> 'FileWrapper':
        return self

    def __next__(self) -> bytes:
        data = self.stream.read(self.buffer_size)
        if data:
            return data
        raise StopIteration


class FileStorage:
    """A thin wrapper over incoming files."""

    def __init__(self,
                 stream: BytesIO,
                 name: str,
                 filename: str,
                 headers: Optional[dict] = None) -> None:
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
        if os.path.isdir(dst):
            filepath = os.path.join(dst, self.secure_filename(self.raw_filename))
        else:
            filepath = dst

        if os.path.exists(filepath) and not overwrite:
            raise IOError(500, 'File exists: {}.'.format(filepath))

        offset = self.stream.tell()

        with open(filepath, 'wb') as fp:
            stream = self.stream
            while True:
                buf = stream.read(4096)
                if not buf:
                    break
                fp.write(buf)

        self.stream.seek(offset)


HTTP_STATUS_LINES = {
    key: f'{key} {value}'
    for key, value in responses.items()
}


class Request:
    """
    Represents an incoming WSGI HTTP request, with headers and body
    taken from the WSGI environment.
    """

    MAX_BODY_SIZE = 1024 * 1024 * 4

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

    def get_header(self, name: str) -> Optional[str]:
        return self.headers.get(name.upper().replace('_', '-'))

    # noinspection PyPep8Naming
    @cached_property
    def GET(self) -> dict:
        return {
            key: squeeze(value)
            for key, value in parse_qs(self.query_string).items()
        }

    # noinspection PyPep8Naming
    @cached_property
    def POST(self) -> dict:
        fields = cgi.FieldStorage(fp=self.body,
                                  environ=self._environ,
                                  keep_blank_values=True)
        # NOTE: we hold an extra reference to avoid some bugs in `cgi.FieldStorage`
        self.__dict__['_cgi.FieldStorage'] = fields

        fields = fields.list or []
        post = dict()

        for item in fields:
            if item.filename:
                post[item.name] = FileStorage(item.file, item.name,
                                              item.filename, item.headers)
            else:
                post[item.name] = item.value
        return post

    @cached_property
    def json(self) -> Optional[dict]:
        ctype = self.content_type.lower().split(';')[0]
        if ctype != 'application/json':
            return None

        try:
            return json.loads(self.body)
        except (ValueError, TypeError) as err:
            raise HTTPError(400, 'Invalid JSON', exception=err)

    @cached_property
    def cookies(self) -> dict:
        http_cookie = self._environ.get('HTTP_COOKIE', '')
        return {
            cookie.key: unquote(cookie.value)
            for cookie in SimpleCookie(http_cookie).values()
        }

    @property
    def body(self) -> Union[BytesIO, TemporaryFile]:
        self._get_body.seek(0)
        return self._get_body

    @cached_property
    def _get_body(self) -> Union[BytesIO, TemporaryFile]:
        # NOTE: For simplicity we do not parse chunked data
        chunked = 'chunked' in self.headers.get('TRANSFER-ENCODING', '')
        if chunked:
            raise NotImplementedError('Chunked data are not supported')

        stream = self._environ['wsgi.input']

        if self.content_length > self.MAX_BODY_SIZE:
            fp = TemporaryFile()
        else:
            fp = BytesIO()

        max_read = max(0, self.content_length)
        while True:
            bs = stream.read(min(max_read, 8192))
            if not bs:
                break
            fp.write(bs)
            max_read -= len(bs)

        fp.seek(0)
        self._environ['wsgi.input'] = fp
        return fp

    def __iter__(self) -> Iterable:
        return iter(self._environ)

    def __len__(self) -> int:
        return len(self._environ)

    def __str__(self) -> str:
        return '<{}: {} {}>'.format(self.__class__.__name__, self.method, self.path)


class Response:
    """Represents an outgoing WSGI HTTP response with body, status, and headers."""

    default_status_code = 200
    default_content_type = 'text/html; charset=UTF-8'

    def __init__(self,
                 data: Union[str, bytes],
                 headers: Optional[dict] = None) -> None:
        self.status_code = self.default_status_code
        self._cookies = SimpleCookie()
        self._headers = {}

        # init data
        if isinstance(data, str):
            data = data.encode()

        self.set_header('Content-Length', str(len(data)))
        self.data = [data]

        # init headers
        if headers:
            for key, value in headers.items():
                if isinstance(value, (list, tuple)):
                    for item in value:
                        self.add_header(key, item)
                elif isinstance(value, str):
                    self.add_header(key, value)

    def get_header(self, name: str) -> Optional[str]:
        rv = self._headers.get(tr(name))
        if rv is None:
            return None
        return squeeze(rv)

    def set_header(self, name: str, value: str) -> None:
        self._headers[tr(name)] = [value]

    def add_header(self, name: str, value: str) -> None:
        self._headers.setdefault(tr(name), []).append(value)

    def unset_header(self, name: str) -> None:
        del self._headers[tr(name)]

    def has_header(self, name: str) -> bool:
        return tr(name) in self._headers

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def header_list(self) -> List[Tuple[str, str]]:
        """ WSGI conform list of (header, value) tuples. """
        headers = list(self._headers.items())

        if 'Content-Type' not in self._headers:
            headers.append(('Content-Type', [self.default_content_type]))

        headers = [(name, val) for (name, values) in headers for val in values]

        if self._cookies:
            for cookie in self._cookies.values():
                headers.append(('Set-Cookie', cookie.OutputString()))

        return headers

    @property
    def status_line(self) -> str:
        return HTTP_STATUS_LINES.get(self.status_code, f'{self.status_code} Unknown')

    def set_cookie(
        self,
        name: str,
        value: str,
        path: str = '/',
        secure: bool = False,
        httponly: bool = False,
        domain: Optional[str] = None,
        max_age: Optional[int] = None,
        # expires: Optional[Union[str, datetime, int, float]] = None,
        # same_site: Optional[str] = None,
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

    def unset_cookie(self, name: str, **kw) -> None:
        kw['max_age'] = -1
        # kw['expires'] = 0
        self.set_cookie(name, '', **kw)

    def __str__(self) -> str:
        rv = ''
        for name, value in self.header_list:
            rv += '{}: {}\n'.format(name.title(), value.strip())
        return rv


class JSONResponse(Response):
    """An HTTP response that serializes data to JSON."""

    def __init__(self,
                 data: Union[list, dict],
                 headers: Optional[dict] = None,
                 **kw) -> None:
        data = json.dumps(data, **kw).encode()
        super().__init__(data, headers)
        self.set_header('Content-Type', 'application/json')


class FileResponse(Response):
    """A streaming HTTP response optimized for files."""

    def __init__(
        self,
        filename: str,
        root_path: str,
        headers: Optional[dict] = None,
        request: Optional[Request] = None,
        downloadable: bool = False,
    ) -> None:
        super().__init__('', headers)
        self.root_path = root_path = os.path.abspath(root_path)
        self.file_path = file_path = os.path.abspath(
            os.path.join(root_path, filename))
        self.check_file()

        stats = os.stat(file_path)
        self.set_header('Content-Length', str(stats.st_size))

        mimetype, encoding = mimetypes.guess_type(filename)
        if mimetype:
            self.set_header('Content-Type', mimetype)
        else:
            self.set_header('Content-Type', 'application/octet-stream')
        if encoding:
            self.set_header('Content-Encoding', encoding)

        if downloadable:
            self.set_header('Content-Disposition',
                            'attachment; filename="%s"' % filename)

        if request:
            # checks etags
            etag = '{}:{}:{}:{}'.format(stats.st_dev, stats.st_ino, stats.st_mtime, filename)
            etag = hashlib.sha1(etag.encode()).hexdigest()
            self.set_header('ETag', etag)

            # NOTE: some browsers may not send 'If-None-Match',
            # if they see 'HTTP/1.0' in status line.
            if request.get_header('IF-NONE-MATCH') == etag:
                self.status_code = 304
                return

            # check more headers like 'If-Modified-Since', 'Accept-ranges'...

        self.data = FileWrapper(open(file_path, 'rb'))

    def check_file(self) -> None:
        if not self.file_path.startswith(self.root_path):
            raise HTTPError(403, 'Access denied.')
        if not os.path.exists(self.file_path) or not os.path.isfile(
                self.file_path):
            raise HTTPError(404, 'File does not exist.')
        if not os.access(self.file_path, os.R_OK):
            raise HTTPError(403, 'No permission to access the file.')


class Redirect(Response):
    """Represents an HTTP response with 301 or 303."""

    def __init__(self,
                 redirect_to: str,
                 status_code: int = 301,
                 headers: Optional[dict] = None):
        assert status_code in (301, 303), 'status code must be in (301, 303)'

        super().__init__('', headers)
        self.status_code = status_code
        self.set_header('Location',
                        quote(redirect_to, safe="/#%[]=:;$&()+,!?*@'~"))


class HTTPError(Response, Exception):
    """Represents an HTTP response with 4xx or 5xx. It can also be raised."""

    def __init__(self,
                 status_code: int = 500,
                 description: Optional[str] = None,
                 exception: Optional[Exception] = None,
                 headers: Optional[dict] = None):
        assert status_code in range(400, 600), 'status code must be 4XX or 5XX'

        super(HTTPError,
              self).__init__(description or HTTP_STATUS_LINES[status_code],
                             headers)
        super(Exception, self).__init__(description)
        self.status_code = status_code
        self.exception = exception

    def __str__(self):
        return "<{} '{}'>".format(type(self).__name__, self.status_line)


class Router:
    """A Router is used to match a request to a function."""

    patterns = [
        (r'<\w+>', r'([\\w-]+)'),
        (r'<\w+:\s*int>', r'(\\d+)'),
        (r'<\w+:\s*path>', r'([\\w\\./-]+)'),
    ]

    def __init__(self) -> None:
        self.rules = []

    def add(self, rule: str, method: str, func: Callable) -> None:
        for pat, repl in self.patterns:
            rule = re.sub(pat, repl, rule)
        rule = '^' + rule + '$'
        self.rules.append([re.compile(rule), method, func])

    def match(self, path: str, method: str) -> Tuple[Callable, tuple]:
        path_matched = False
        for rule, mtd, func in self.rules:
            match = rule.match(path)
            if match:
                path_matched = True
                if method == mtd:
                    args = match.groups()
                    return func, args

        if path_matched:
            raise HTTPError(405)
        else:
            raise HTTPError(404)

    def __str__(self) -> str:
        return str(self.rules)


class MiniWeb:
    """
    Represents a web application and consists of routes, decorators and configuration.
    Instances are callable WSGI applications.
    """

    def __init__(self, config: Optional[dict] = None):
        self.router = Router()
        self.error_handlers = {}
        self.config = config or {}

    def add_rule(self, rule: str, method: str, func: Callable) -> None:
        self.router.add(rule, method, func)

    def route(self, rule: str, method: Union[str, List[str]]) -> Callable:
        def wrapper(func):
            if isinstance(method, list):
                for mtd in method:
                    self.add_rule(rule, mtd, func)
            else:
                self.add_rule(rule, method, func)
            return func

        return wrapper

    def get(self, rule: str) -> Callable:
        return self.route(rule, 'GET')

    def post(self, rule: str) -> Callable:
        return self.route(rule, 'POST')

    def put(self, rule: str) -> Callable:
        return self.route(rule, 'PUT')

    def delete(self, rule: str) -> Callable:
        return self.route(rule, 'DELETE')

    def error(self, status_code: int) -> Callable:
        def wrapper(func):
            self.error_handlers[status_code] = func
            return func

        return wrapper

    def serve_static(self,
                     root_path: str,
                     url_prefix: str = '/static',
                     headers: Optional[dict] = None) -> None:
        self.add_rule(
            url_prefix + '/<filename:path>',
            'GET', lambda request, filename: FileResponse(
                filename, root_path, headers, request))

    def wsgi(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        request = Request(environ)
        try:
            func, args = self.router.match(request.path, request.method)
            response = self._cast(func(request, *args))
        except HTTPError as err:
            logging.exception(err)
            response = err
        except Exception as err:
            logging.exception(err)
            response = HTTPError(500, exception=err)

        if isinstance(response, HTTPError):
            result = self._handle_error(request, response)
            if result:
                response = result

        start_response(response.status_line, response.header_list)
        return response.data

    def run(self, host='127.0.0.1', port=9000):
        from wsgiref.simple_server import make_server

        sys.stderr.write('Server running on http://{}:{}/\n'.format(host, port))
        server = make_server(host, port, self)
        server.serve_forever()

    def __call__(self, environ: dict, start_response: Callable):
        return self.wsgi(environ, start_response)

    @staticmethod
    def _cast(response: Any) -> Response:
        if isinstance(response, Response):
            return response
        if isinstance(response, (str, bytes)):
            return Response(response)
        if isinstance(response, (list, dict)):
            return JSONResponse(response)
        raise ValueError('Unrecognized response')

    def _handle_error(self, req: Request, error: HTTPError) -> Optional[Any]:
        handler = self.error_handlers.get(error.status_code)
        if handler:
            result = handler(req, error)
            if result:
                return self._cast(result)
