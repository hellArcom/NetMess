from gevent import pywsgi
from app import app 

http_server = pywsgi.WSGIServer(('0.0.0.0', 5000), app)
http_server.serve_forever()


print("LE SERVER A CRACH :/")
input()