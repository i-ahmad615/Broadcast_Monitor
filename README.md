# Broadcast Monitor

Broadcast Monitor is a Python tool that listens to live network traffic, detects Ethernet broadcast packets, logs packet details to CSV, and can send SMTP email alerts when a broadcast is found.

## Requirements

- Python 3.10+ installed
- `tshark` installed and available on `PATH`
- Git installed

If you want email alerts, you also need valid SMTP credentials in a `.env` file.

## Clone And Run

Run the following commands from PowerShell on Windows.

```powershell
git clone https://github.com/i-ahmad615/broadcast_monitor.git
cd broadcast_monitor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python main.py
```

If PowerShell blocks the virtual environment activation script, run this once in the same window and then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Configure Email Alerts

Edit the `.env` file after copying it from `.env.example`:

```env
EMAIL_ADDRESS=your-email@example.com
EMAIL_PASSWORD=your-app-password
RECIPIENT_EMAIL=recipient@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
```

Email alerts are optional. If the SMTP values are missing, the monitor will still run and will only log detections locally.

## Running the Monitor

**Option 1: From Command Line**
```powershell
cd c:\Users\ahmed\Desktop\broadcast_monitor
.\.venv\Scripts\Activate.ps1
python main.py
```

**Option 2: Using the Batch File**
Double-click `start_monitor.bat` in the project folder to start the monitor automatically.

## What It Does

- Captures live traffic with `tshark` through `pyshark`
- Filters for ARP/broadcast traffic and extracts packet details
- Writes detected broadcasts to `logs/broadcasts.csv`
- Sends an email alert when SMTP settings are configured

## Project Structure

- `main.py` - application entry point
- `config.py` - environment configuration loader
- `packet_capture.py` - live packet capture helpers
- `detector.py` - broadcast detection and packet field extraction
- `logger.py` - logging setup
- `email_service.py` - email notification sender
- `utils/helpers.py` - shared helper functions
- `logs/broadcasts.csv` - generated CSV log output

## Notes

- Keep `tshark` installed and on `PATH`, otherwise packet capture cannot start.
- The `logs` folder is created automatically if it does not already exist.
