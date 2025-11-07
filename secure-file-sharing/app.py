from flask import Flask, request, send_file, render_template_string, flash, redirect, url_for
from Crypto.Cipher import AES
import io
import base64

app = Flask(__name__)
app.secret_key = "supersecretkey"

KEY = b"thisisasecretkey"  # 16 bytes AES key

HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>🔒 Secure File Sharing</title>
  <style>
    body {
      font-family: 'Poppins', sans-serif;
      background: linear-gradient(135deg, #667eea, #764ba2);
      color: #fff;
      text-align: center;
      padding: 40px;
    }
    h1 {
      font-size: 2.5rem;
      margin-bottom: 10px;
    }
    .container {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 30px;
      max-width: 500px;
      margin: auto;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    }
    form {
      margin: 20px 0;
    }
    input[type="file"] {
      padding: 10px;
      border: none;
      border-radius: 5px;
      background: #fff;
      color: #333;
      width: 80%;
      margin-bottom: 15px;
    }
    input[type="submit"] {
      background: #00c9a7;
      border: none;
      padding: 10px 20px;
      color: white;
      font-weight: bold;
      border-radius: 8px;
      cursor: pointer;
      transition: 0.3s;
    }
    input[type="submit"]:hover {
      background: #00b091;
    }
    .message {
      margin-top: 20px;
      background: rgba(255,255,255,0.2);
      padding: 10px;
      border-radius: 8px;
      display: inline-block;
      animation: fadeIn 0.8s ease-in-out;
    }
    a.download-btn {
      display: inline-block;
      background: #00c9a7;
      color: white;
      text-decoration: none;
      padding: 10px 15px;
      border-radius: 8px;
      font-weight: bold;
      margin-top: 10px;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 Secure File Sharing</h1>
    <p>Encrypt and decrypt your files safely using AES encryption.</p>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="message">
          {% for message in messages %}
            {{ message|safe }}
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    
    <h2>Encrypt a File</h2>
    <form method="POST" enctype="multipart/form-data" action="/encrypt">
      <input type="file" name="file" required><br>
      <input type="submit" value="Encrypt File">
    </form>

    <h2>Decrypt a File</h2>
    <form method="POST" enctype="multipart/form-data" action="/decrypt">
      <input type="file" name="file" required><br>
      <input type="submit" value="Decrypt File">
    </form>
  </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    file = request.files.get("file")
    if not file:
        flash("⚠️ No file uploaded!")
        return redirect(url_for("index"))

    data = file.read()
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_data = base64.b64encode(cipher.nonce + tag + ciphertext)
    encrypted_filename = file.filename + ".enc"

    # Store encrypted file in memory for download later
    with open("encrypted_output.enc", "wb") as f:
        f.write(encrypted_data)

    flash(f"✅ File <b>{file.filename}</b> encrypted successfully!<br>"
          f"<a class='download-btn' href='/download/encrypted'>⬇️ Download Encrypted File</a>")
    return redirect(url_for("index"))

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    file = request.files.get("file")
    if not file:
        flash("⚠️ No file uploaded!")
        return redirect(url_for("index"))

    try:
        encrypted_data = base64.b64decode(file.read())
    except Exception:
        flash("❌ Invalid file: not Base64 or corrupted.")
        return redirect(url_for("index"))

    if len(encrypted_data) < 32:
        flash("❌ Invalid or corrupted file.")
        return redirect(url_for("index"))

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)

    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        flash("❌ Decryption failed: wrong key or corrupted file.")
        return redirect(url_for("index"))

    decrypted_filename = file.filename.replace(".enc", "")
    with open("decrypted_output", "wb") as f:
        f.write(data)

    flash(f"✅ File <b>{decrypted_filename}</b> decrypted successfully!<br>"
          f"<a class='download-btn' href='/download/decrypted'>⬇️ Download Decrypted File</a>")
    return redirect(url_for("index"))

@app.route("/download/<filetype>")
def download_file(filetype):
    if filetype == "encrypted":
        return send_file("encrypted_output.enc", as_attachment=True)
    elif filetype == "decrypted":
        return send_file("decrypted_output", as_attachment=True)
    else:
        return "Invalid file type", 400

if __name__ == "__main__":
    print("🚀 Starting Flask app at http://127.0.0.1:5000")
    app.run(debug=True)
