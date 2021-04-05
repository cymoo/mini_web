"""A minimum web framework"""

from typing import *
from urllib.parse import unquote


HTTP_STATUS_CODES = {
    200: 'OK',
    301: 'Moved Permanently',
    303: 'See Other',
    400: 'Bad Request',
    404: 'Not Found',
    500: 'Internal Server Error',
}


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
    def remote_addr(self) -> str:
        return self._environ.get('REMOTE_ADDR', '0.0.0.0')

    @property
    def query_string(self) -> str:
        return self._environ.get('QUERY_STRING', '')

    @property
    def method(self) -> str:
        return self._environ['REQUEST_METHOD']

    @property
    def path_info(self) -> str:
        return unquote(self._environ.get('PATH_INFO', ''))

    @property
    def host(self) -> str:
        return self._environ.get('HTTP_HOST', '')

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
    def form(self):
        pass

    @cached_property
    def files(self):
        pass

    @cached_property
    def json(self):
        pass


class BaseResponse:
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
    pass


class MiniWeb:
    pass
