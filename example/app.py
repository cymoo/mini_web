from web import MiniWeb, Request, Response, FileResponse, JSONResponse, Redirect, HTTPError
import os
from pprint import pprint

app = MiniWeb()

app.serve_static(os.path.dirname(__file__))


@app.get('/')
def index(req: Request):
    pprint(req._environ)
    resp = Response('hello world')
    resp.set_cookie('foo', 'bar')
    return resp


@app.get('/foo/<num:int>')
def foo(req: Request, num: str):
    print('cookie:')
    print(req.cookies['foo'])
    return num


@app.get('/files/<filepath:path>')
def bar(req: Request, filepath: str):
    print(filepath)
    return FileResponse(filepath, os.path.dirname(__file__))


@app.get('/json')
def index(req: Request):
    print(req.cookies)
    return {'status': 'ok', 'message': '你好啊'}


@app.get('/redirect')
def redirect(req: Request):
    return Redirect('http://www.baidu.com')


@app.get('/file')
def file(req: Request):
    return FileResponse('example/app.py', os.path.dirname(__file__))


@app.route('/upload', method=['GET', 'POST'])
def upload(req: Request):
    if req.method == 'GET':
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
    else:
        # print(req.POST)
        # print(req.POST['file'])
        req.POST['file'].save(os.path.dirname(__file__))
        req.POST['file'].save(os.path.dirname(__file__) + '/foo.txt')
        # print('why....')
        # print(req.POST['file'].stream.read())
        return {'status': 'ok', 'message': 'file uploaded'}


@app.route('/form', method=['GET', 'POST'])
def form(req: Request):
    form_type = req.GET.get('type')
    if form_type == 'form-data':
        enctype = 'multipart/form-data'
    else:
        enctype = 'application/x-www-form-urlencoded'

    if req.method == 'GET':
        return f"""
            <html>
                <head><title>upload file</title></head>
                <body>
                    <h1>upload file</h1>
                    <form action="/form" method="post" enctype="{enctype}">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <hr>
                        <button type="submit">submit</button>
                    </form>
                </body>
            </html>
        """
    else:
        return {
            'name': req.POST['username'],
            'password': req.POST['password']
        }


@app.error(404)
def handle_404(req: Request, err: HTTPError):
    resp = JSONResponse({'status': 'failed', 'message': 'page not found'})
    resp.status_code = 404
    return resp


# app.run(port=5000)

if __name__ == '__main__':
    from server import MiniServer

    ms = MiniServer(('127.0.0.1', 7777))
    ms.set_app(app.wsgi)
    ms.run_forever()
