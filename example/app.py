from web import MiniWeb, Request, Response


app = MiniWeb()


@app.get('/')
def index(req: Request):
    return 'hello world'


app.run()