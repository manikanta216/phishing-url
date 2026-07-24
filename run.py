import webbrowser
import threading
from waitress import serve
from app import app

def open_browser():
    webbrowser.open_new('http://localhost:5000')

if __name__ == '__main__':
    print("==================================================")
    print("  PhishShield Server Started!")
    print("  Opening browser automatically at http://localhost:5000")
    print("==================================================")
    threading.Timer(1.0, open_browser).start()
    serve(app, host='127.0.0.1', port=5000)
