import os
import sys
import subprocess
import secrets
import logging
from pathlib import Path
import threading

# ---------------------------------------------------------
# Logging Configuration: Terminal + File
# ---------------------------------------------------------
log_file = "cyber_sentinel_runtime.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SetupWizard")

def print_banner():
    logger.info("="*65)
    logger.info("🛡️  CYBER SENTINEL - PRODUCTION SETUP & LAUNCH WIZARD 🛡️")
    logger.info("="*65)

def check_python_version():
    """Validates if the user is running Python 3.9 or higher."""
    req_major, req_minor = 3, 9
    curr_major, curr_minor = sys.version_info.major, sys.version_info.minor
    
    logger.info(f"[*] Checking Python Version... Found {curr_major}.{curr_minor}")
    if curr_major < req_major or (curr_major == req_major and curr_minor < req_minor):
        logger.error(f"[!] Error: Cyber Sentinel requires Python {req_major}.{req_minor} or higher.")
        logger.error("[!] Please upgrade your Python installation and try again.")
        sys.exit(1)
    logger.info("[✓] Python version is compatible.\n")

def prompt_installation():
    """Prompts the user to install Python and Node.js dependencies."""
    logger.info("[?] Do you want to automatically install all required dependencies?")
    logger.info("    This includes: FastAPI, Uvicorn, Gemini SDK, and React Node Modules.")
    choice = input("👉 Proceed with installation? (y/n): ").strip().lower()
    
    if choice == 'y':
        logger.info("\n[*] Starting Backend Python Installations...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            logger.info("[✓] Backend libraries installed successfully.\n")
        except subprocess.CalledProcessError as e:
            logger.error(f"[!] Failed to install Python requirements: {e}")
            sys.exit(1)
            
        logger.info("[*] Starting Frontend React (Node.js) Installations...")
        frontend_path = os.path.join(os.getcwd(), "frontend", "ui")
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        
        try:
            subprocess.check_call([npm_cmd, "install"], cwd=frontend_path)
            logger.info("[✓] Frontend node modules installed successfully.\n")
        except subprocess.CalledProcessError as e:
            logger.error(f"[!] Failed to install Frontend Node modules: {e}")
            logger.error("[!] Make sure Node.js is installed on your system.")
            sys.exit(1)
    else:
        logger.info("[*] Skipping installation phase.\n")

def setup_environment():
    """Checks for .env file and prompts the user for keys if missing."""
    env_path = Path(".env")
    if env_path.exists():
        logger.info("[*] Environment file (.env) found. API Keys are ready.\n")
        return

    logger.info("[!] First-time setup detected. Let's configure your environment.")
    
    # Prompt for Gemini API Key
    logger.info("    Cyber Sentinel uses the Gemini API for advanced ScamDNA extraction.")
    logger.info("    Get your free key here: https://aistudio.google.com/app/apikey")
    
    while True:
        gemini_key = input("👉 Enter your Gemini API Key: ").strip()
        if gemini_key:
            break
        logger.warning("[!] API Key cannot be empty. Please enter a valid key.")
    
    # Auto-generate a highly secure JWT Secret Key for the police backend
    jwt_secret = secrets.token_urlsafe(64)
    logger.info("\n[*] Automatically generated a secure JWT Secret Key for backend encryption.")
    
    # Write to .env
    with open(env_path, "w") as f:
        f.write(f"GEMINI_API_KEY={gemini_key}\n")
        f.write(f"JWT_SECRET_KEY={jwt_secret}\n")
        
    logger.info("[✓] .env file created and saved successfully!\n")

def stream_logs(process, prefix):
    """Reads stdout and stderr from a subprocess and routes it to Python logging."""
    for line in iter(process.stdout.readline, b''):
        if line:
            logger.info(f"[{prefix}] {line.decode('utf-8').strip()}")

def start_services():
    """Starts both the FastAPI backend and Vite frontend, streaming all logs."""
    logger.info("="*65)
    logger.info("🚀 INITIATING CYBER SENTINEL CORE ENGINE")
    logger.info("="*65)
    logger.info(f"[*] All output will be visible here and saved to {log_file}")
    
    # Start Backend
    backend_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--reload", "--port", "8080"],
        cwd=os.getcwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    
    # Start Frontend
    frontend_path = os.path.join(os.getcwd(), "frontend", "ui")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    frontend_process = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=frontend_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    
    # Launch threads to stream the terminal output of both servers to the logger
    t_backend = threading.Thread(target=stream_logs, args=(backend_process, "BACKEND"), daemon=True)
    t_frontend = threading.Thread(target=stream_logs, args=(frontend_process, "FRONTEND"), daemon=True)
    t_backend.start()
    t_frontend.start()
    
    logger.info("👉 Dashboard URL: http://localhost:5173")
    logger.info("👉 API Docs URL: http://localhost:8080/docs")
    logger.info("Press CTRL+C to shut down all services safely.\n")
    
    try:
        backend_process.wait()
        frontend_process.wait()
    except KeyboardInterrupt:
        logger.info("\n[*] Interruption detected. Shutting down Cyber Sentinel...")
        backend_process.terminate()
        frontend_process.terminate()
        logger.info("[✓] All services stopped securely. Goodbye!")

if __name__ == "__main__":
    print_banner()
    check_python_version()
    prompt_installation()
    setup_environment()
    start_services()
