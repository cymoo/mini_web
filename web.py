"""A minimum web framework"""

import cgi
import hashlib
import json
import mimetypes
import os
import re
import sys
from http.client import responses
from http.cookies import SimpleCookie
from io import BytesIO
from typing import *
from urllib.parse import unquote, parse_qs, quote


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


def tr(key: str) -> str:
    """Normalize HTTP Response header"""
    return key.title().replace('_', '-')


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
            raise HTTPError(500, 'Folder does not exists: %s'.format(dst))

        filepath = os.path.join(dst, self.secure_filename(self.raw_filename))
        if os.path.exists(filepath) and not overwrite:
            raise HTTPError(500, 'File exists: %s.'.format(filepath))

        with open(filepath, 'wb') as fp:
            stream = self.stream
            # TODO: what caused this error: read of closed file?
            while True:
                buf = stream.read(8192)
                if not buf:
                    break
                fp.write(buf)


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

    def get_header(self, name: str) -> Optional[str]:
        return self.headers.get(name.upper().replace('_', '-'))

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
            raise HTTPError(400, 'Invalid JSON')

    @cached_property
    def cookies(self) -> dict:
        http_cookie = self._environ.get('HTTP_COOKIE', '')
        return dict((cookie.key, unquote(cookie.value)) for cookie in SimpleCookie(http_cookie).values())

    # NOTE: we omit parsing 'transfer-encoding: chunked'
    def _get_raw_body(self) -> bytes:
        chunked = 'chunked' in self.headers.get('TRANSFER-ENCODING', '')
        if chunked:
            raise NotImplementedError('Chunked data are not supported')

        stream = self._environ['wsgi.input']
        bytes_length = max(0, self.content_length)
        return stream.read(bytes_length)

    def __iter__(self) -> Iterable:
        return iter(self._environ)

    def __len__(self) -> int:
        return len(self._environ)

    def __str__(self) -> str:
        return '<%s: %s %s>' % (self.__class__.__name__, self.method, self.path)


class Response:
    default_status_code = 200
    default_content_type = 'text/html; charset=UTF-8'

    def __init__(self, data: Union[str, bytes], headers: Optional[dict] = None) -> None:
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
        header = self._headers.get(tr(name))
        if header is None:
            return None
        if len(header) == 1:
            return header[0]
        else:
            return header

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
        return HTTP_STATUS_LINES.get(self.status_code, '%d Unknown' % self.status_code)

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
        for name, value in self.headers.items():
            rv += '%s: %s\n'.format(name.title(), value.strip())
        return rv


class JSONResponse(Response):
    def __init__(self, data: Union[list, dict], headers: Optional[dict] = None, **kw) -> None:
        data = json.dumps(data, **kw).encode()
        super().__init__(data, headers)
        self.set_header('Content-Type', 'application/json')


class FileResponse(Response):
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
        self.file_path = file_path = os.path.abspath(os.path.join(root_path, filename))
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
            self.set_header('Content-Disposition', 'attachment; filename="%s"' % filename)

        if request:
            # checks etags
            etag = '%d:%d:%d:%s' % (stats.st_dev, stats.st_ino, stats.st_mtime, filename)
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
        if not os.path.exists(self.file_path) or not os.path.isfile(self.file_path):
            raise HTTPError(404, 'File does not exist.')
        if not os.access(self.file_path, os.R_OK):
            raise HTTPError(403, 'No permission to access the file.')


class Redirect(Response):
    def __init__(self, redirect_to: str, status_code: int = 301, headers: Optional[dict] = None):
        assert status_code in (301, 303), 'status code must be in (301, 303)'

        super().__init__('', headers)
        self.status_code = status_code
        self.set_header('Location', quote(redirect_to, safe="/#%[]=:;$&()+,!?*@'~"))


class HTTPError(Response, Exception):
    def __init__(
            self,
            status_code: int = 500,
            description: Optional[str] = None,
            exception: Optional[Exception] = None,
            headers: Optional[dict] = None
    ):
        assert status_code in range(400, 600), 'status code must be 4XX or 5XX'
        
        super(HTTPError, self).__init__(description or HTTP_STATUS_LINES[status_code], headers)
        super(Exception, self).__init__(description)
        self.status_code = status_code
        self.exception = exception


class Router:
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
    def __init__(self):
        self.router = Router()
        self.error_handlers = {}

    def add_rule(self, rule: str, method: str, func: Callable) -> None:
        self.router.add(rule, method, func)

    def route(self, rule: str, method: str) -> Callable:
        def wrapper(func):
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

    def error(self, status_code: int):
        def wrapper(func):
            self.error_handlers[status_code] = func
            return func
        return wrapper

    def serve_static(
            self,
            root_path: str,
            url_prefix: str = '/static',
            headers: Optional[dict] = None
    ) -> None:
        self.add_rule(
            url_prefix + '/<filename:path>',
            'GET',
            lambda request, filename: FileResponse(filename, root_path, headers, request)
        )

    def wsgi(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        request = Request(environ)
        try:
            func, args = self.router.match(request.path, request.method)
            response = self._cast(func(request, *args))
        except HTTPError as err:
            print(err)
            response = err
        except Exception as err:
            print(err)
            response = HTTPError(500, exception=err)

        if isinstance(response, HTTPError):
            result = self._handle_error(request, response)
            if result:
                response = result

        start_response(response.status_line, response.header_list)
        return response.data

    def run(self, host='127.0.0.1', port=9000):
        from wsgiref.simple_server import make_server

        sys.stderr.write('Server running on http://%s:%d/\n' % (host, port))
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


if __name__ == '__main__':
    from pprint import pprint
    app = MiniWeb()

    app.serve_static(os.path.dirname(__file__))

    @app.get('/')
    def index(req: Request):
        return 'hello world'

    @app.post('/foo/<num:int>')
    def foo(req: Request, num: str):
        return num

    @app.get('/files/<filepath:path>')
    def bar(req: Request, filepath: str):
        print(filepath)
        return FileResponse(filepath, os.path.dirname(__file__))

    @app.get('/json')
    def index(req: Request):
        print(req.cookies)
        return {'status': 'ok', 'message': 'hello world'}

    @app.get('/redirect')
    def redirect(req: Request):
        return Redirect('http://www.baidu.com')

    @app.get('/file')
    def file(req: Request):
        return FileResponse('example/app.py', os.path.dirname(__file__))

    @app.get('/upload')
    def upload(req: Request):
        return """
        <html>
            <head><title>upload file</title></head>
            <body>
                <h1>upload file</h1>
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <input type="file" name="file" />
                    <hr>
                    <button type="submit">submit</button>
                </form>
            </body>
        </html>
        """

    @app.post('/upload')
    def upload(req: Request):
        print(req.POST)
        req.POST['file'].save(os.path.dirname(__file__))
        return {'status': 'ok', 'message': 'file uploaded'}

    @app.error(404)
    def handle_404(req: Request, err: HTTPError):
        resp = JSONResponse({'status': 'failed', 'message': 'page not found'})
        resp.status_code = 404
        return resp

    app.run(port=5000)
