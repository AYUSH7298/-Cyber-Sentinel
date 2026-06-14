import subprocess
import time
import socket
import sys
import webbrowser
import os

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(('127.0.0.1', port)) == 0

def launch():
    print("\n" + "=" * 50)
    print("[SECURE] GURUGRAM POLICE - CYBER SENTINEL LAUNCHER")
    print("=" * 50)
    
    # Get directory details
    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)
    
    # 1. Start backend if not already running
    if is_port_open(8080):
        print("[*] Status: FastAPI backend is ALREADY running on port 8080.")
    else:
        print("[*] Status: FastAPI backend is OFFLINE. Starting server...")
        # Start uvicorn in background, redirecting output to uvicorn.log
        log_file = open("uvicorn.log", "w")
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8080"],
            stdout=log_file,
            stderr=subprocess.STDOUT
        )
        
        # Wait for backend port to open
        backend_started = False
        for i in range(15):
            print(f"    Waiting for backend to bind to port 8080 (attempt {i+1}/15)...")
            time.sleep(1)
            if is_port_open(8080):
                print("[+] Success: FastAPI backend started successfully!")
                backend_started = True
                break
        
        if not backend_started:
            print("[-] Warning: Backend did not start within timeout. Attempting to proceed...")

    # 2. Start Streamlit dashboard
    if is_port_open(8501):
        print("[*] Status: Streamlit dashboard is ALREADY running on port 8501.")
        print("[*] Opening browser...")
        webbrowser.open("http://localhost:8501")
    else:
        print("[*] Status: Streamlit dashboard is OFFLINE. Starting server...")
        # Start streamlit in background
        subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "dashboard/app_ui.py", "--server.port", "8501"]
        )
        
        # Wait a moment for dashboard to bind
        time.sleep(3)
        print("[+] Success: Streamlit dashboard launched!")
        print("[*] Opening browser...")
        webbrowser.open("http://localhost:8501")
        
    print("=" * 50)
    print("Active Links:")
    print("   - Frontend Dashboard: http://localhost:8501")
    print("   - Backend API Docs:   http://localhost:8080/docs")
    print("=" * 50)
    print("Press Ctrl+C to close this launcher console.")
    print("(Note: Dashboard and Backend servers will continue running in background.)\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Closing launcher. Goodbye!")

if __name__ == "__main__":
    launch()
