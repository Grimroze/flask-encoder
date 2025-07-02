from flask import Flask, render_template, request
import base64

app = Flask(__name__)

def encode(key, message):
    enc = []
    for i in range(len(message)):
        key_c = key[i % len(key)]
        enc.append(chr((ord(message[i]) + ord(key_c)) % 256))
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, message):
    try:
        message = base64.urlsafe_b64decode(message).decode()
    except Exception:
        return "Invalid encoded format!"
    dec = []
    for i in range(len(message)):
        key_c = key[i % len(key)]
        dec.append(chr((256 + ord(message[i]) - ord(key_c)) % 256))
    return "".join(dec)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['key']
        mode = request.form['mode']

        if not message or not key or not mode:
            result = "Please fill all fields!"
        else:
            if mode == 'encode':
                result = encode(key, message)
            elif mode == 'decode':
                result = decode(key, message)
            else:
                result = "Invalid Mode"
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
