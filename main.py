import os
import sys
import threading
import queue
import logging
import zipfile
import json
import subprocess
import yaml
import re
import socket
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, jsonify, Response,
    send_file, redirect, url_for, session, send_from_directory
)

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload


def load_config():
    defaults = {
        "server": {"port": 25810},
        "download": {"max_speed": "0"}
    }
    if not os.path.exists("config.yml"):
        return defaults
    try:
        with open("config.yml", "r") as f:
            return yaml.safe_load(f)
    except:
        return defaults


CFG = load_config()


def parse_speed_limit(speed_str):
    if not speed_str or str(speed_str) == "0":
        return None

    s = str(speed_str).lower().strip()
    if re.match(r"^\d+[kmg]$", s):
        return s.upper()

    val = re.findall(r"[\d\.]+", s)
    if not val:
        return None

    val = float(val[0])

    if "gbps" in s:
        return f"{int((val * 1000) / 8)}M"
    if "mbps" in s:
        mb = val / 8
        return f"{int(mb * 1000)}K" if mb < 1 else f"{round(mb, 2)}M"
    if "kbps" in s:
        return f"{int(val / 8)}K"

    return None


def find_available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.secret_key = 'u3u7dndh8wkwbx7pwbdbwo1o3730dbdd'

CLIENT_SECRETS_FILE = 'client_secrets.json'
SCOPES = ['https://www.googleapis.com/auth/drive.file']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

log_queue = queue.Queue()
last_downloaded_files = []

STORAGE_DIR = "storage"
COOKIES_FILE = "auth/tiktok-cookies.txt"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs("auth", exist_ok=True)


def get_smart_domain_folder(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        if "tiktok" in domain:
            return "tiktok.com"
        if "youtu" in domain:
            return "youtube.com"
        if "instagram" in domain:
            return "instagram.com"
        if "facebook" in domain or "fb.watch" in domain:
            return "facebook.com"
        if "x.com" in domain or "twitter" in domain:
            return "twitter.com"
        return domain
    except:
        return "others"


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


def upload_worker(filepath, creds_dict, q):
    try:
        filename = os.path.basename(filepath)
        parent = os.path.basename(os.path.dirname(filepath))
        drive_name = f"{parent}_{filename}"

        q.put(f"[drive] upload start: {filename}")
        creds = Credentials(**creds_dict)
        service = build('drive', 'v3', credentials=creds)
        media = MediaFileUpload(filepath, resumable=True)
        service.files().create(
            body={'name': drive_name},
            media_body=media,
            fields='id'
        ).execute()
        q.put(f"[drive] upload ok: {filename}")
    except Exception as e:
        q.put(f"[drive] upload failed: {e}")


def download_func(url, q):
    global last_downloaded_files
    last_downloaded_files = []

    domain_folder = get_smart_domain_folder(url)
    target_dir = os.path.join(STORAGE_DIR, domain_folder)
    os.makedirs(target_dir, exist_ok=True)

    raw_speed = CFG.get('download', {}).get('max_speed', 0)
    limit_arg = parse_speed_limit(raw_speed)

    downloaded_paths = []

    if domain_folder == "tiktok.com":
        if not os.path.exists(COOKIES_FILE):
            q.put("[error] tiktok cookies missing")
            q.put("ALL_DONE")
            return

        cmd = [
            sys.executable, "-m", "gallery_dl",
            "--cookies", COOKIES_FILE,
            "--directory", target_dir,
            "--filename", "{user}/{id}_{num:>02}.{extension}",
            "--no-mtime",
            url
        ]

        if limit_arg:
            cmd += ["--download-rate", limit_arg]

    else:
        cmd = [
            sys.executable, "-m", "yt_dlp",
            "--ignore-config", "--newline",
            "-o", f"{target_dir}/%(uploader)s/%(title)s.%(ext)s",
            url
        ]

        if limit_arg:
            cmd += ["--limit-rate", limit_arg]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            line = line.strip()
            q.put(line)

            if "Destination:" in line:
                downloaded_paths.append(line.split("Destination: ")[1])
            elif "has already been downloaded" in line:
                downloaded_paths.append(line.split("[download] ")[1].split(" has")[0])
            elif 'Merging formats into "' in line:
                downloaded_paths = [line.split('"')[1]]

        proc.wait()
    except Exception as e:
        q.put(f"[error] downloader crash: {e}")

    valid_files = [
        f for f in downloaded_paths
        if os.path.exists(f) and not f.endswith('.part')
    ]

    if not valid_files:
        import time
        now = time.time()
        for root, _, files in os.walk(target_dir):
            for file in files:
                p = os.path.join(root, file)
                if now - os.path.getmtime(p) < 30:
                    valid_files.append(p)

    if not valid_files:
        q.put("error: no media found")
        q.put("ALL_DONE")
        return

    valid_files = sorted(set(valid_files))
    last_downloaded_files = valid_files
    rel = [os.path.relpath(f, STORAGE_DIR) for f in valid_files]

    videos = [f for f in valid_files if f.endswith(('.mp4', '.webm', '.mkv'))]
    if len(videos) == 1 and len(valid_files) == 1:
        q.put("JSON_DATA:" + json.dumps({"type": "video", "files": rel}))
        q.put("ALL_DONE_VIDEO")
    else:
        q.put("JSON_DATA:" + json.dumps({"type": "slides", "files": rel}))
        q.put("ALL_DONE_PHOTO")


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.get_json() or request.form
        url = data.get("url")
        if not url:
            return jsonify({"error": "URL empty"}), 400
        with log_queue.mutex:
            log_queue.queue.clear()
        threading.Thread(target=download_func, args=(url, log_queue)).start()
        return jsonify({"status": "started"})
    return render_template("index.html")


@app.route('/files/<path:filename>')
def serve_file(filename):
    return send_from_directory(STORAGE_DIR, filename)


@app.route('/download_zip')
def download_zip():
    if not last_downloaded_files:
        return "No files", 404
    zip_path = os.path.join(STORAGE_DIR, "bundle.zip")
    with zipfile.ZipFile(zip_path, 'w') as z:
        for f in last_downloaded_files:
            z.write(f, os.path.relpath(f, STORAGE_DIR))
    return send_file(zip_path, as_attachment=True)


@app.route('/check_auth_upload')
def check_auth_upload():
    if 'credentials' not in session:
        return jsonify({'status': 'need_auth', 'auth_url': url_for('authorize')})

    creds = session['credentials']
    targets = [f for f in last_downloaded_files if os.path.exists(f)]
    if not targets:
        return jsonify({'status': 'error'})

    def uploader():
        for f in targets:
            upload_worker(f, creds, log_queue)
        log_queue.put("ALL_DONE_DRIVE")

    threading.Thread(target=uploader).start()
    return jsonify({'status': 'started'})


@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    auth_url, state = flow.authorization_url(
        access_type='offline', prompt='consent'
    )
    session['state'] = state
    return redirect(auth_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)
    session['credentials'] = credentials_to_dict(flow.credentials)
    return redirect(url_for('index'))


@app.route('/stream')
def stream():
    def gen():
        while True:
            try:
                yield f"data: {log_queue.get(timeout=0.5)}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
    return Response(gen(), mimetype="text/event-stream")


if __name__ == "__main__":
    env_port = os.environ.get("PORT")
    cfg_port = CFG.get('server', {}).get('port', 25810)

    if env_port:
        final_port = int(env_port)
    elif str(cfg_port).lower() == "auto":
        final_port = find_available_port()
    else:
        final_port = int(cfg_port)

    app.run(host="0.0.0.0", port=final_port, debug=True)
