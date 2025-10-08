#!/usr/bin/env python3
import os
import socket
from flask import Flask, send_from_directory

app = Flask(__name__)

# Get the directory where the script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def serve_tutorial():
    """Serve the hooking tutorial HTML file"""
    return send_from_directory(BASE_DIR, 'hooking_beginners_guide.html')

@app.route('/<path:filename>')
def serve_file(filename):
    """Serve any other files in the directory"""
    return send_from_directory(BASE_DIR, filename)

def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    local_ip = get_local_ip()
    port = 8080
    
    print("\n" + "="*60)
    print("🚀 Flask Server Starting...")
    print("="*60)
    print(f"\n📚 Serving: Function Hooking Tutorial")
    print(f"\n🌐 Access the tutorial at:")
    print(f"   Local:    http://127.0.0.1:{port}/")
    print(f"   Network:  http://{local_ip}:{port}/")
    print("\n💡 Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    # Run the Flask server
    app.run(host='0.0.0.0', port=port, debug=False)