import re
from typing import *


# s1 = r'/a/(\w+)/(\d+)/([\w/]+)'

url = '/a/f-b/123/path/to/file'
pat = re.compile('/a/([\\w-]+)/(\\d+)/([\\w/-]+)')

output = pat.match(url)
print(output.groups())

str_seg = r'<\w+>'
int_seg = r'<\w+:\s*int>'
pah_seg = r'<\w+:\s*path>'

s = '/a/<arg1>/<arg2:int>/<arg3:path>'
s = re.sub(str_seg, r'([\\w-]+)', s)
s = re.sub(int_seg, r'(\\d+)', s)
s = re.sub(pah_seg, r'([\\w/-]+)', s)

print(s)
print('/a/([\\w-]+)/(\\d+)/([\\w/-]+)')
print(re.compile(s).match(url).groups())


class Router:
    mapping = [
        (r'<\w+>', r'([\\w-]+)'),
        (r'<\w+:\s*int>', r'(\\d+)'),
        (r'<\w+:\s*path>', r'([\\w\\./-]+)'),
    ]
    patterns = re.compile(r'(<\w+>)|(<\w+:\s*int>)|(<\w+:\s*path>)')

    def __init__(self) -> None:
        self.rules = []

    def add(self, rule: str, method: str, func: Callable) -> None:
        # for pat, repl in self.patterns:
        #     rule = re.sub(pat, repl, rule)
        # rule = '^' + rule + '$'
        # self.rules.append([re.compile(rule), method, func])
        for pat in self.patterns.split(rule):
            if not pat: continue
            pass

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
            raise Exception(405)
        else:
            raise Exception(404)


# pattern = re.compile(r'(aa)|(bb)')
#
# s = '123aa456bb789'
# print(pattern.split(s))

router = Router()
router.add('/foo/<bar>/a-<num:int>/<file:path>', 'GET', lambda x: x)
