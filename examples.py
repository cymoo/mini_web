import os
from random import random
from web import (
    MiniWeb,
    Request,
    Response,
    FileResponse,
    JSONResponse,
    Redirect,
    HTTPError
)

app = MiniWeb()

app.serve_static(os.path.dirname(__file__))


# hello world
@app.get('/')
def index(req: Request):
    return 'hello world'


# variable url
@app.get('/user/<name>')
def user(req: Request, name: str):
    print(req.GET.get('page'))
    # a list or dict will be cast to a `JSONResponse`.
    return {
        'status': 'ok',
        'message': f'Hello, {name}; your ip: {req.remote_addr}'
    }


# set header
@app.get('/set-header')
def set_header(req: Request):
    resp = Response('hello world')
    resp.set_header('X-Powered-By', 'MiniWeb')
    resp.set_cookie('foo', 'bar')
    # cookie can be then fetched using `req.cookies['foo']`
    return resp


# redirect
@app.get('/redirect')
def redirect(req: Request):
    return Redirect('https://www.bing.com')


# send file
@app.get('/file')
def send_file(req: Request):
    return FileResponse('examples.py', os.path.dirname(__file__))


# raise error
@app.get('/error')
def raise_error(req: Request):
    if random() > 0.5:
        raise HTTPError(500, 'Oops, you are unlucky')
    else:
        return 'a lucky boy'


# handle error
@app.error(404)
def handle_404(req: Request, err: HTTPError):
    resp = JSONResponse({
        'status': 'failed',
        'message': 'page not found'
    })
    resp.status_code = 404
    return resp


# upload file and save it
@app.route('/upload', methods=['GET', 'POST'])
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
        req.POST['file'].save(os.path.dirname(__file__))
        return {'status': 'ok', 'message': 'file uploaded'}


# get form args
@app.route('/form', methods=['GET', 'POST'])
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


if __name__ == '__main__':
    app.run()
