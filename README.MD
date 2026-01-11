# Fetcher

Fetcher is a robust, web-based All-In-One (AIO) media extraction tool powered by Flask. It acts as a unified frontend for **yt-dlp** and **gallery-dl**, allowing users to scrape, download, and process media from major platforms (TikTok, YouTube, Instagram, X/Twitter, Facebook) with ease.

Beyond local downloading, Fetcher features a **cloud-native pipeline** that allows users to upload processed media directly to **Google Drive** using seamless OAuth 2.0 authentication.

---

## 🛠️ Prerequisites

Ensure your environment meets the following requirements:

1. **Python 3.10+**
2. **FFmpeg** (Required for media merging)
   - **Linux**: `sudo apt install ffmpeg`
   - **Windows**: Download binaries and add to System PATH.
   - **macOS**: `brew install ffmpeg`

---

## 📦 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/fetcher.git
   cd fetcher
   ```

2. **Set Up Virtual Environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## ⚙️ Configuration

### 1. General Settings (`config.yml`)

Create a `config.yml` file in the root directory to manage server behavior and network throttling.

```yaml
server:
  # Options:
  # - 25810 (Specific integer port)
  # - "auto" (Randomly assigns an available free port)
  port: 25810

download:
  # Network Throttling / Rate Limiting
  # Examples: "5 mbps", "500 kbps", "10M" (MB/s).
  # Set to "0" for Unlimited speed (Brutal Mode).
  max_speed: "0"
```

### 2. Google OAuth Credentials

To enable the **"Save to Drive"** feature:

- Go to the [Google Cloud Console](https://console.cloud.google.com/).
- Create a project and enable the **Google Drive API**.
- Create **OAuth 2.0 Client credentials** (Web Application).
- Add the authorized redirect URI:  
  `http://localhost:25810/oauth2callback`  
  *(Adjust the port if you changed it in `config.yml`)*
- Download the JSON file, rename it to `client_secrets.json`, and place it in the root directory.

> 🔒 **Never commit `client_secrets.json` to version control!**

### 3. Cookies (Critical for TikTok/Instagram)

To avoid `403 Forbidden` errors or bot detection:

- Export cookies from your browser using a **"Netscape Cookie"** extension (e.g., [Get cookies.txt](https://chrome.google.com/webstore/detail/get-cookiestxt/bgaddhkoddajcdgocldbbfleckgcbcid)).
- Save the file as `auth/tiktok-cookies.txt`.

> You may also create `auth/instagram-cookies.txt` if needed.

---

## ▶️ Usage

Execute the entry point script:

```bash
python main.py
```

**Console Output Example**:
```
=============================================
🚀 FETCHER IS RUNNING
📡 Local Access : http://localhost:25810
🔌 Port Used    : 25810
⚡ Rate Limit   : UNLIMITED (Full Speed)
=============================================
```

Open your browser and navigate to the URL provided in the terminal.

---

## 🏗️ Technical Architecture

### Backend Logic
- **Flask Server**: Handles HTTP requests, session management, and SSE streams.
- **Subprocess Management**: Spawns isolated `yt-dlp` or `gallery-dl` processes to ensure thread safety.
- **Log Parsing**: Captures `stdout` from subprocesses in real-time, filters relevant progress data, and pushes it to a `queue.Queue`.
- **Stream Endpoint**: The `/stream` route yields data from the queue to the frontend via `EventSource`.

### Directory Structure
```
fetcher/
├── auth/
│   └── tiktok-cookies.txt          # Authentication cookies
├── storage/                        # Temporary download buffer
│   ├── tiktok.com/
│   └── youtube.com/
├── templates/
│   └── index.html                  # Frontend UI
├── config.yml                      # Server & Speed config
├── main.py                         # Core application logic
├── requirements.txt                # Python dependencies
└── client_secrets.json             # Google OAuth secrets (Do not commit!)
```

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**. The user assumes all responsibility for complying with the **Terms of Service** of the respective media platforms and applicable **copyright laws**.
