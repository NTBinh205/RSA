from flask import Flask, render_template_string, request, send_file, redirect, url_for, flash
import base64
import io
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'replace-this-with-a-secure-key'  # Required for flash messages

SIGN_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Người Ký - Ký và Xuất File</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet"/>
  <style>
    :root {
      --color-primary: #4F46E5;
      --color-primary-hover: #4338CA;
      --color-background: #f4f6fb;
      --color-card-bg: #ffffff;
      --color-text: #1F2937;
      --color-text-muted: #6B7280;
      --color-accent: #6366F1;
      --color-success: #16A34A;
      --color-error: #DC2626;
      --border-radius: 16px;
      --spacing-unit: 24px;
      --shadow-light: 0 6px 12px rgba(0,0,0,0.08);
      --shadow-hover: 0 12px 24px rgba(79, 70, 229, 0.24);
      font-family: 'Inter', sans-serif;
    }
    body {
      margin: 0;
      background-color: var(--color-background);
      color: var(--color-text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    header {
      background: var(--color-primary);
      color: white;
      padding: var(--spacing-unit);
      font-weight: 700;
      font-size: 1.8rem;
      text-align: center;
      letter-spacing: 0.03em;
      box-shadow: 0 6px 12px rgba(79, 70, 229, 0.38);
      user-select: none;
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 12px;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    header .material-icons {
      font-size: 2.4rem;
      transform: translateY(2px);
      filter: drop-shadow(0 0 2px rgba(0,0,0,0.15));
    }
    main {
      flex-grow: 1;
      max-width: 800px;
      margin: 2rem auto 3rem auto;
      padding: 0 1rem;
      display: flex;
      flex-direction: column;
      gap: var(--spacing-unit);
    }
    section {
      background: var(--color-card-bg);
      border-radius: var(--border-radius);
      box-shadow: var(--shadow-light);
      padding: var(--spacing-unit);
      display: flex;
      flex-direction: column;
      transition: box-shadow 0.3s ease;
    }
    section:hover {
      box-shadow: var(--shadow-hover);
    }
    h2 {
      margin-top: 0;
      font-weight: 700;
      font-size: 1.5rem;
      color: var(--color-primary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
      user-select: none;
    }
    h2 .material-icons {
      font-size: 2rem;
      color: var(--color-primary);
      flex-shrink: 0;
    }
    label {
      margin-top: 1rem;
      margin-bottom: 0.5rem;
      font-weight: 600;
      color: var(--color-text);
      user-select: none;
      display: block;
    }
    input[type=file], textarea {
      width: 100%;
      font-family: 'Inter', sans-serif;
      font-size: 1rem;
      padding: 10px 14px;
      border: 2px solid #CBD5E1;
      border-radius: 12px;
      outline-offset: 2px;
      outline-color: transparent;
      transition: border-color 0.25s ease;
      resize: vertical;
      background: var(--color-card-bg);
      color: var(--color-text);
    }
    input[type=file]:focus, 
    textarea:focus {
      border-color: var(--color-primary);
      outline-color: var(--color-primary);
    }
    button {
      margin-top: 1.5rem;
      background: var(--color-primary);
      color: white;
      font-weight: 700;
      border: none;
      cursor: pointer;
      padding: 14px 28px;
      font-size: 1.1rem;
      border-radius: 14px;
      transition: background-color 0.3s ease, box-shadow 0.25s ease;
      align-self: flex-start;
      box-shadow: 0 3px 8px rgba(79, 70, 229, 0.4);
      user-select: none;
    }
    button:disabled {
      background: #aaa;
      cursor: not-allowed;
      box-shadow: none;
    }
    button:hover:not(:disabled) {
      background: var(--color-primary-hover);
      box-shadow: 0 6px 20px rgba(79, 70, 229, 0.6);
    }
    textarea {
      min-height: 120px;
      font-family: monospace;
      color: #334155;
      box-shadow: inset 0 1px 3px rgb(0 0 0 / 0.06);
    }
    .status {
      margin-top: 1rem;
      font-weight: 700;
      color: var(--color-success);
      user-select: none;
      font-size: 1.1rem;
    }
    nav {
      margin-top: 1rem;
      font-size: 1rem;
    }
    nav a {
      color: var(--color-primary);
      text-decoration: none;
      font-weight: 600;
      margin-right: 1rem;
    }
    nav a:hover {
      text-decoration: underline;
    }
    .alert {
      margin-top: 1rem;
      color: var(--color-error);
      font-weight: 600;
    }
  </style>
</head>
<body>
  <header role="banner">
    <span class="material-icons" aria-hidden="true">edit_note</span>
    Người Ký - Ký và Xuất File
  </header>
  <main>
    <section>
      <h2><span class="material-icons">upload_file</span> Chọn tệp và ký</h2>
      <form method="POST" action="/sign" enctype="multipart/form-data" id="signForm">
        <label for="file">Chọn tệp cần ký:</label>
        <input type="file" id="file" name="file" required aria-required="true" />
        <button type="submit">Tạo cặp khóa & ký tệp</button>
      </form>
      {% if error %}
        <div class="alert" role="alert">{{ error }}</div>
      {% endif %}
      {% if public_key and signed_package %}
        <h3>Khóa Công (gửi cho người nhận):</h3>
        <textarea rows="8" style="width:100%" readonly>{{public_key}}</textarea>
        <h3>Gói Dữ Liệu Đã Ký (gửi cho người nhận):</h3>
        <textarea rows="14" style="width:100%" readonly>{{signed_package}}</textarea>
        <p class="status">Bạn có thể gửi 2 phần trên cho người nhận để xác minh và tải về tệp gốc nếu chữ ký hợp lệ.</p>
      {% endif %}
    </section>
    <nav aria-label="Điều hướng">
      <a href="/verify">Chuyển sang Người Nhận - Xác Minh và Tải về</a>
    </nav>
  </main>
</body>
</html>
"""

VERIFY_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Người Nhận - Xác Minh Chữ Ký & Tải File</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet"/>
  <style>
    :root {
      --color-primary: #4F46E5;
      --color-primary-hover: #4338CA;
      --color-background: #f4f6fb;
      --color-card-bg: #ffffff;
      --color-text: #1F2937;
      --color-text-muted: #6B7280;
      --color-accent: #6366F1;
      --color-success: #16A34A;
      --color-error: #DC2626;
      --border-radius: 16px;
      --spacing-unit: 24px;
      --shadow-light: 0 6px 12px rgba(0,0,0,0.08);
      --shadow-hover: 0 12px 24px rgba(79, 70, 229, 0.24);
      font-family: 'Inter', sans-serif;
    }
    body {
      margin: 0;
      background-color: var(--color-background);
      color: var(--color-text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    header {
      background: var(--color-primary);
      color: white;
      padding: var(--spacing-unit);
      font-weight: 700;
      font-size: 1.8rem;
      text-align: center;
      letter-spacing: 0.03em;
      box-shadow: 0 6px 12px rgba(79, 70, 229, 0.38);
      user-select: none;
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 12px;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    header .material-icons {
      font-size: 2.4rem;
      transform: translateY(2px);
      filter: drop-shadow(0 0 2px rgba(0,0,0,0.15));
    }
    main {
      flex-grow: 1;
      max-width: 800px;
      margin: 2rem auto 3rem auto;
      padding: 0 1rem;
      display: flex;
      flex-direction: column;
      gap: var(--spacing-unit);
    }
    section {
      background: var(--color-card-bg);
      border-radius: var(--border-radius);
      box-shadow: var(--shadow-light);
      padding: var(--spacing-unit);
      display: flex;
      flex-direction: column;
      transition: box-shadow 0.3s ease;
    }
    section:hover {
      box-shadow: var(--shadow-hover);
    }
    h2 {
      margin-top: 0;
      font-weight: 700;
      font-size: 1.5rem;
      color: var(--color-primary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
      user-select: none;
    }
    h2 .material-icons {
      font-size: 2rem;
      color: var(--color-primary);
      flex-shrink: 0;
    }
    label {
      margin-top: 1rem;
      margin-bottom: 0.5rem;
      font-weight: 600;
      color: var(--color-text);
      user-select: none;
      display: block;
    }
    textarea {
      width: 100%;
      font-family: monospace;
      font-size: 1rem;
      padding: 10px 14px;
      border: 2px solid #CBD5E1;
      border-radius: 12px;
      outline-offset: 2px;
      outline-color: transparent;
      transition: border-color 0.25s ease;
      resize: vertical;
      background: var(--color-card-bg);
      color: var(--color-text);
      min-height: 120px;
      box-shadow: inset 0 1px 3px rgb(0 0 0 / 0.06);
    }
    textarea:focus {
      border-color: var(--color-primary);
      outline-color: var(--color-primary);
    }
    button {
      margin-top: 1.5rem;
      background: var(--color-primary);
      color: white;
      font-weight: 700;
      border: none;
      cursor: pointer;
      padding: 14px 28px;
      font-size: 1.1rem;
      border-radius: 14px;
      transition: background-color 0.3s ease, box-shadow 0.25s ease;
      align-self: flex-start;
      box-shadow: 0 3px 8px rgba(79, 70, 229, 0.4);
      user-select: none;
    }
    button:disabled {
      background: #aaa;
      cursor: not-allowed;
      box-shadow: none;
    }
    button:hover:not(:disabled) {
      background: var(--color-primary-hover);
      box-shadow: 0 6px 20px rgba(79, 70, 229, 0.6);
    }
    .status {
      margin-top: 1rem;
      font-weight: 700;
      user-select: none;
      font-size: 1.1rem;
    }
    .status.good {
      color: var(--color-success);
    }
    .status.bad {
      color: var(--color-error);
    }
    nav {
      margin-top: 1rem;
      font-size: 1rem;
    }
    nav a {
      color: var(--color-primary);
      text-decoration: none;
      font-weight: 600;
      margin-right: 1rem;
    }
    nav a:hover {
      text-decoration: underline;
    }
    .alert {
      margin-top: 1rem;
      color: var(--color-error);
      font-weight: 600;
    }
  </style>
</head>
<body>
  <header role="banner">
    <span class="material-icons" aria-hidden="true">verified_user</span>
    Người Nhận - Xác Minh chữ ký & Tải về
  </header>
  <main>
    <section>
      <h2><span class="material-icons">download</span> Xác minh và tải tệp gốc</h2>
      <form method="POST" action="/verify" enctype="multipart/form-data" id="verifyForm">
        <label for="signed_package">Dán hoặc tải lên Gói Dữ Liệu Đã Ký (JSON):</label>
        <textarea id="signed_package" name="signed_package" rows="8" placeholder="Dán gói dữ liệu đã ký hoặc chọn file JSON tải lên"></textarea>
        <input type="file" id="signed_package_file" name="signed_package_file" accept=".json" />
        
        <label for="public_key">Dán Khóa Công của Người gửi:</label>
        <textarea id="public_key" name="public_key" rows="8" placeholder="Dán khóa công .pem ở đây" required ></textarea>

        <button type="submit">Xác minh và tải tệp gốc</button>
      </form>
      {% if error %}
        <div class="alert" role="alert">{{ error }}</div>
      {% endif %}
      {% if verified %}
        <p class="status good">✔ Chữ ký hợp lệ. Tải tệp gốc bên dưới.</p>
        <a href="{{ url_for('download_original') }}" download="{{ original_filename }}" style="font-weight:700; font-size:1.1rem; text-decoration:none; color:var(--color-primary);">⬇ Tải xuống: {{ original_filename }}</a>
      {% elif verified is not none %}
        <p class="status bad">✘ Chữ ký không hợp lệ hoặc lỗi xác minh.</p>
      {% endif %}
    </section>
    <nav aria-label="Điều hướng">
      <a href="/">Chuyển sang Người Ký - Tải lên và ký</a>
    </nav>
    <script>
      // If user selects a file for signed package, fill textarea and clear file input on change
      const signedFileInput = document.getElementById('signed_package_file');
      const signedTextarea = document.getElementById('signed_package');
      signedFileInput.addEventListener('change', () => {
        const file = signedFileInput.files[0];
        if(!file) return;
        const reader = new FileReader();
        reader.onload = e => {
          signedTextarea.value = e.target.result;
        };
        reader.readAsText(file);
      });
    </script>
  </main>
</body>
</html>
"""

# Storage for original file to allow download after verification
# In real app, store in DB or cache, here simple in-memory (single user demo)
STORAGE = {
    "original_file": None,
    "filename": None,
}


@app.route('/')
def sign():
    return render_template_string(SIGN_TEMPLATE, public_key=None, signed_package=None, error=None)


@app.route('/sign', methods=['POST'])
def sign_post():
    file = request.files.get('file')
    if not file:
        return render_template_string(SIGN_TEMPLATE, error="Vui lòng chọn tệp để ký.", public_key=None, signed_package=None)
    file_content = file.read()
    filename = secure_filename(file.filename) or 'file'

    # Generate keys RSA 2048
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Sign file content w/ PSS padding & SHA256
    signature = private_key.sign(
        file_content,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Serialize public key PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Package signed data as base64 JSON: file content + signature + filename
    package = {
        "filename": filename,
        "file_content_b64": base64.b64encode(file_content).decode("utf-8"),
        "signature_b64": base64.b64encode(signature).decode("utf-8"),
    }
    package_json = json.dumps(package, indent=2)

    # Send to client for download or copy
    return render_template_string(SIGN_TEMPLATE, public_key=public_pem, signed_package=package_json, error=None)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    verified = None
    error = None
    original_file = None
    original_filename = None

    if request.method == 'POST':
        signed_package_text = request.form.get('signed_package', '').strip()
        # If user uploaded file for package, use file content instead
        file_package = request.files.get('signed_package_file')
        if file_package and file_package.filename != '':
            try:
                signed_package_text = file_package.read().decode('utf-8')
            except Exception as ex:
                error = f"Lỗi đọc file gói dữ liệu: {ex}"
                return render_template_string(VERIFY_TEMPLATE, error=error, verified=None)

        public_key_pem = request.form.get('public_key', '').strip()
        if not signed_package_text or not public_key_pem:
            error = "Vui lòng cung cấp gói dữ liệu đã ký và khóa công."
            return render_template_string(VERIFY_TEMPLATE, error=error, verified=None)

        try:
            package = json.loads(signed_package_text)
            filename = package["filename"]
            file_content = base64.b64decode(package["file_content_b64"])
            signature = base64.b64decode(package["signature_b64"])
        except Exception as ex:
            error = "Dữ liệu gói ký không hợp lệ hoặc lỗi giải mã JSON."
            return render_template_string(VERIFY_TEMPLATE, error=error, verified=None)

        try:
            # Load public key PEM
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
            # Verify signature
            public_key.verify(
                signature,
                file_content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            verified = True
            # Store original file in memory for download route
            STORAGE["original_file"] = file_content
            STORAGE["filename"] = filename
            original_filename = filename
        except InvalidSignature:
            verified = False
        except Exception as ex:
            error = f"Lỗi xác minh chữ ký: {ex}"
            verified = False

    return render_template_string(VERIFY_TEMPLATE, error=error, verified=verified, original_filename=original_filename)


@app.route('/download')
def download_original():
    original_file = STORAGE.get("original_file")
    filename = STORAGE.get("filename") or "file"
    if original_file is None:
        return "Không có tệp để tải về. Vui lòng xác minh chữ ký trước.", 404
    # send file as attachment
    return send_file(io.BytesIO(original_file), as_attachment=True, download_name=filename)


if __name__ == '__main__':
    app.run(debug=True)

