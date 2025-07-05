from flask import Flask, render_template, request, jsonify
import base64
import hashlib
import hmac
import os
import logging
from datetime import datetime
import secrets
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    HOST = os.environ.get('FLASK_HOST', '127.0.0.1')
    PORT = int(os.environ.get('FLASK_PORT', 5000))


app.config.from_object(Config)


#Encoding strategies 
class EncoderError(Exception):
    """Custom exception for encoding errors"""
    pass


def validate_inputs(key, message):
    """Validate inputs before processing"""
    if not key or not message:
        raise EncoderError("Key and message cannot be empty")
    if len(key) < 3:
        raise EncoderError("Key must be at least 3 characters long")
    if len(message) > 10000:
        raise EncoderError("Message too long (max 10000 characters)")
    return True


def safe_base64_encode(data):
    """Safely encode data to base64"""
    try:
        return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')
    except Exception as e:
        raise EncoderError(f"Encoding error: {str(e)}")


def safe_base64_decode(data):
    """Safely decode base64 data"""
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except Exception as e:
        raise EncoderError(f"Decoding error: Invalid format or corrupted data")


def derive_key(key, length=32):
    """Derive a secure key using PBKDF2"""
    salt = b'grimroze_salt_2025'  # In production, use random salt
    return hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), salt, 100000, length)


def caesar_encode(key, message):
    """Enhanced Caesar cipher with proper key derivation"""
    validate_inputs(key, message)
    derived_key = derive_key(key, 1)
    shift = derived_key[0] % 95  # Printable ASCII range

    encoded = []
    for char in message:
        if 32 <= ord(char) <= 126:  # Printable ASCII
            encoded.append(chr(((ord(char) - 32 + shift) % 95) + 32))
        else:
            encoded.append(char)  # Keep non-printable chars as is

    return safe_base64_encode(''.join(encoded))


def caesar_decode(key, message):
    """Enhanced Caesar cipher decoder"""
    validate_inputs(key, message)
    try:
        decoded_message = safe_base64_decode(message)
        derived_key = derive_key(key, 1)
        shift = derived_key[0] % 95

        decoded = []
        for char in decoded_message:
            if 32 <= ord(char) <= 126:
                decoded.append(chr(((ord(char) - 32 - shift) % 95) + 32))
            else:
                decoded.append(char)

        return ''.join(decoded)
    except Exception as e:
        raise EncoderError(f"Caesar decode error: {str(e)}")


def xor_encode(key, message):
    """Enhanced XOR cipher with proper key derivation"""
    validate_inputs(key, message)
    derived_key = derive_key(key, len(message))

    encoded = []
    for i, char in enumerate(message):
        encoded.append(chr(ord(char) ^ derived_key[i % len(derived_key)]))

    return safe_base64_encode(''.join(encoded))


def xor_decode(key, message):
    """Enhanced XOR cipher decoder"""
    validate_inputs(key, message)
    try:
        decoded_message = safe_base64_decode(message)
        derived_key = derive_key(key, len(decoded_message))

        decoded = []
        for i, char in enumerate(decoded_message):
            decoded.append(chr(ord(char) ^ derived_key[i % len(derived_key)]))

        return ''.join(decoded)
    except Exception as e:
        raise EncoderError(f"XOR decode error: {str(e)}")


def vigenere_encode(key, message):
    """Enhanced Vigenère cipher"""
    validate_inputs(key, message)
    derived_key = derive_key(key, len(key))

    encoded = []
    for i, char in enumerate(message):
        if 32 <= ord(char) <= 126:  # Printable ASCII
            key_char = derived_key[i % len(derived_key)] % 95
            encoded.append(chr(((ord(char) - 32 + key_char) % 95) + 32))
        else:
            encoded.append(char)

    return safe_base64_encode(''.join(encoded))


def vigenere_decode(key, message):
    """Enhanced Vigenère cipher decoder"""
    validate_inputs(key, message)
    try:
        decoded_message = safe_base64_decode(message)
        derived_key = derive_key(key, len(key))

        decoded = []
        for i, char in enumerate(decoded_message):
            if 32 <= ord(char) <= 126:
                key_char = derived_key[i % len(derived_key)] % 95
                decoded.append(chr(((ord(char) - 32 - key_char) % 95) + 32))
            else:
                decoded.append(char)

        return ''.join(decoded)
    except Exception as e:
        raise EncoderError(f"Vigenère decode error: {str(e)}")


def advanced_encode(key, message):
    """Advanced multi-layer encoding"""
    validate_inputs(key, message)

    # Layer 1: XOR with derived key
    derived_key = derive_key(key, len(message))
    layer1 = ''.join(chr(ord(c) ^ derived_key[i % len(derived_key)]) for i, c in enumerate(message))

    # Layer 2: Caesar shift
    shift = sum(derived_key) % 95
    layer2 = ''.join(chr(((ord(c) - 32 + shift) % 95) + 32) if 32 <= ord(c) <= 126 else c for c in layer1)

    # Layer 3: Base64 with checksum
    checksum = hmac.new(key.encode(), layer2.encode(), hashlib.sha256).hexdigest()[:8]
    final = f"{checksum}:{layer2}"

    return safe_base64_encode(final)


def advanced_decode(key, message):
    """Advanced multi-layer decoder"""
    validate_inputs(key, message)
    try:
        # Decode base64
        decoded = safe_base64_decode(message)

        # Extract checksum and data
        if ':' not in decoded:
            raise EncoderError("Invalid format - missing checksum")

        checksum, data = decoded.split(':', 1)

        # Verify checksum
        expected_checksum = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()[:8]
        if checksum != expected_checksum:
            raise EncoderError("Invalid key or corrupted data")

        # Reverse Layer 2: Caesar shift
        derived_key = derive_key(key, len(data))
        shift = sum(derived_key) % 95
        layer1 = ''.join(chr(((ord(c) - 32 - shift) % 95) + 32) if 32 <= ord(c) <= 126 else c for c in data)

        # Reverse Layer 1: XOR
        original = ''.join(chr(ord(c) ^ derived_key[i % len(derived_key)]) for i, c in enumerate(layer1))

        return original
    except Exception as e:
        raise EncoderError(f"Advanced decode error: {str(e)}")


# Encoder registry
ENCODERS = {
    'caesar': (caesar_encode, caesar_decode, "Classic Caesar cipher with secure key derivation"),
    'xor': (xor_encode, xor_decode, "XOR cipher with PBKDF2 key stretching"),
    'vigenere': (vigenere_encode, vigenere_decode, "Vigenère cipher with enhanced security"),
    'advanced': (advanced_encode, advanced_decode, "Multi-layer encryption with integrity check"),
}


# === API Routes ===
@app.route('/api/encode', methods=['POST'])
def api_encode():
    """API endpoint for encoding"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        message = data.get('message', '').strip()
        key = data.get('key', '').strip()
        method = data.get('method', 'advanced').lower()

        if method not in ENCODERS:
            return jsonify({'error': f'Invalid method. Available: {list(ENCODERS.keys())}'}), 400

        encode_func, _, _ = ENCODERS[method]
        result = encode_func(key, message)

        logger.info(f"Encoded message using {method} method")
        return jsonify({
            'success': True,
            'result': result,
            'method': method,
            'timestamp': datetime.now().isoformat()
        })

    except EncoderError as e:
        logger.warning(f"Encoder error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error in encode: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/decode', methods=['POST'])
def api_decode():
    """API endpoint for decoding"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        message = data.get('message', '').strip()
        key = data.get('key', '').strip()
        method = data.get('method', 'advanced').lower()

        if method not in ENCODERS:
            return jsonify({'error': f'Invalid method. Available: {list(ENCODERS.keys())}'}), 400

        _, decode_func, _ = ENCODERS[method]
        result = decode_func(key, message)

        logger.info(f"Decoded message using {method} method")
        return jsonify({
            'success': True,
            'result': result,
            'method': method,
            'timestamp': datetime.now().isoformat()
        })

    except EncoderError as e:
        logger.warning(f"Decoder error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error in decode: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/methods', methods=['GET'])
def api_methods():
    """Get available encoding methods"""
    methods = {
        method: {
            'name': method.capitalize(),
            'description': desc
        }
        for method, (_, _, desc) in ENCODERS.items()
    }
    return jsonify(methods)


# === Web Routes ===
@app.route('/', methods=['GET', 'POST'])
def index():
    """Main web interface"""
    result = ""
    error = ""
    encoder_methods = list(ENCODERS.keys())
    selected_method = request.form.get('encoder', 'advanced')
    message = request.form.get('message', '')
    key = request.form.get('key', '')
    mode = request.form.get('mode', 'encode')

    if request.method == 'POST':
        try:
            if not message.strip() or not key.strip():
                error = "Please fill all fields!"
            elif selected_method not in ENCODERS:
                error = "Invalid encoding method!"
            else:
                encode_func, decode_func, _ = ENCODERS[selected_method]
                if mode == 'encode':
                    result = encode_func(key, message)
                elif mode == 'decode':
                    result = decode_func(key, message)
                else:
                    error = "Invalid mode selected!"

        except EncoderError as e:
            error = str(e)
            logger.warning(f"Encoder error in web interface: {str(e)}")
        except Exception as e:
            error = "An unexpected error occurred. Please try again."
            logger.error(f"Unexpected error in web interface: {str(e)}")

    return render_template('index.html',
                           result=result,
                           error=error,
                           encoder_methods=encoder_methods,
                           selected_method=selected_method,
                           message=message,
                           key=key,
                           mode=mode,
                           encoders_info=ENCODERS)


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(
        debug=Config.DEBUG,
        host=Config.HOST,
        port=Config.PORT
    )





