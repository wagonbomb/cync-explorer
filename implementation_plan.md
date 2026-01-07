# Cync Web GUI Controller - Implementation Plan

## Goal
Create a modern, user-friendly Web GUI to control GE Cync lights. This will replace the command-line interface with a visual dashboard that lists all discovered lights and allows individual ON/OFF control.

## User Review Required
> [!NOTE]
> The GUI will run as a local web server (http://localhost:8080). You will need to open this address in your browser.

## Proposed Changes

### 1. Requirements
#### [MODIFY] [requirements.txt](file:///C:/Users/Meow/.gemini/antigravity/scratch/cync-explorer/requirements.txt)
- Add `aiohttp` for the async web server

### 2. Backend (Python)
#### [NEW] [cync_server.py](file:///C:/Users/Meow/.gemini/antigravity/scratch/cync-explorer/cync_server.py)
- **Web Server**: Uses `aiohttp` to serve the static frontend and API endpoints.
- **API Endpoints**:
    - `GET /api/scan`: Runs the enhanced BLE scanner and returns a JSON list of devices (including aliases).
    - `POST /api/control`: Accepts `{mac, action, value}` to control lights via BLE.
- **BLE Management**:
    - Maintains a background loop for BLE connections (using `BleakClient`).
    - managing a queue of commands to avoid conflicts.

### 3. Frontend (HTML/JS/CSS)
#### [NEW] [static/index.html](file:///C:/Users/Meow/.gemini/antigravity/scratch/cync-explorer/static/index.html)
- **Design**: Premium "Glassmorphism" dark mode UI.
- **Features**:
    - "Scan" button with loading animation.
    - Card grid layout for discovered lights.
    - Toggle switches for ON/OFF.
    - Real-time status updates.
    - Group control (All On / All Off).

## Verification Plan

### Automated Tests
- None for the GUI itself.
- Validating the server starts and serves HTML.

### Manual Verification
1.  **Start Server**: Run `python cync_server.py`.
2.  **Open Browser**: Go to `http://localhost:8080`.
3.  **Scan**: Click "Scan for Lights" and verify devices appear.
4.  **Control**: Click the toggle on a light and verify it turns On/Off.
