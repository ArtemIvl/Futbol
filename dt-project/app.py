from flask import Flask
from views import views
import os

app = Flask(__name__, static_url_path='/static')
app.secret_key = os.urandom(24).hex()
app.register_blueprint(views, url_prefix='/views')

if __name__ == '__main__':
    app.run(debug=True, port = 8000)
 