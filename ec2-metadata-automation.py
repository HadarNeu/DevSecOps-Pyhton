from flask import Flask, jsonify
import platform
import datetime
import psutil
import os

app = Flask(__name__)

@app.route('/metadata', methods=['GET'])
def get_metadata():
    metadata = {
        'timestamp': datetime.datetime.now().isoformat(),
        'hostname': platform.node(),
        'platform': platform.system(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': {
            'total': psutil.virtual_memory().total,
            'available': psutil.virtual_memory().available,
            'percent': psutil.virtual_memory().percent
        },
        'process_id': os.getpid()
    }
    return jsonify(metadata)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)