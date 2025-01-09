import psutil
import ctypes
from ctypes import wintypes
import threading
import logging
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# Constants for Windows API
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MAX_MODULES = 1024
MAX_PATH = 260
LIST_MODULES_ALL = 0x03

# Load necessary DLLs
psapi = ctypes.WinDLL('Psapi.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')

# Define function prototypes for Windows API
psapi.EnumProcessModulesEx.restype = wintypes.BOOL
psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD, wintypes.DWORD
]

psapi.GetModuleFileNameExW.restype = wintypes.DWORD
psapi.GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD
]

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

# Logging configuration
logging.basicConfig(
    filename='dll_detection_advanced.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Globals
suspicious_dlls = ["injected.dll", "hack.dll", "cheat.dll"]
trusted_processes = ["explorer.exe", "svchost.exe", "taskmgr.exe"]
scan_results = []

# Email configuration
EMAIL_ENABLED = False
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USERNAME = "youremail@gmail.com"
EMAIL_PASSWORD = "yourpassword"
EMAIL_RECEIVER = "receiveremail@gmail.com"


# Utility Functions
def send_email_alert(results):
    """Send an email alert with the suspicious DLL details."""
    if not EMAIL_ENABLED:
        return

    try:
        body = json.dumps(results, indent=4)
        msg = MIMEText(body)
        msg['Subject'] = "Suspicious DLL Injection Detected"
        msg['From'] = EMAIL_USERNAME
        msg['To'] = EMAIL_RECEIVER

        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USERNAME, EMAIL_RECEIVER, msg.as_string())

        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


def get_loaded_modules(pid):
    """Retrieve the list of DLLs loaded into a process."""
    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        return None  # Unable to open process

    modules = (wintypes.HMODULE * MAX_MODULES)()
    cb_needed = wintypes.DWORD()

    if psapi.EnumProcessModulesEx(
        h_process, ctypes.byref(modules), ctypes.sizeof(modules), ctypes.byref(cb_needed), LIST_MODULES_ALL
    ):
        num_modules = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
        module_list = []
        for i in range(num_modules):
            module_name = ctypes.create_unicode_buffer(MAX_PATH)
            if psapi.GetModuleFileNameExW(h_process, modules[i], module_name, MAX_PATH):
                module_list.append(module_name.value)
        kernel32.CloseHandle(h_process)
        return module_list
    else:
        kernel32.CloseHandle(h_process)
        return None


def detect_injected_dlls(pid, name):
    """Check if a process has any suspicious DLLs injected."""
    if name.lower() in [proc.lower() for proc in trusted_processes]:
        return None

    modules = get_loaded_modules(pid)
    if modules is None:
        return None

    detected_dlls = []
    for module in modules:
        for dll in suspicious_dlls:
            if dll.lower() in module.lower():
                detected_dlls.append(module)

    if detected_dlls:
        return {"pid": pid, "name": name, "suspicious_dlls": detected_dlls}
    return None


# Multithreading
def scan_process(proc):
    try:
        pid = proc.info['pid']
        name = proc.info['name']
        result = detect_injected_dlls(pid, name)
        if result:
            scan_results.append(result)
            logging.warning(f"[ALERT] Suspicious DLLs detected in process {name} (PID: {pid}): {result['suspicious_dlls']}")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass


# Real-time monitoring
def real_time_monitor():
    """Continuously monitor for injected DLLs in real-time."""
    print("Starting real-time DLL injection monitoring...")
    try:
        while True:
            threads = []
            for proc in psutil.process_iter(['pid', 'name']):
                thread = threading.Thread(target=scan_process, args=(proc,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            if scan_results:
                print("\nSuspicious DLLs detected:")
                for result in scan_results:
                    print(f"Process: {result['name']} (PID: {result['pid']})")
                    for dll in result['suspicious_dlls']:
                        print(f"  - {dll}")
                send_email_alert(scan_results)
                export_results()
                scan_results.clear()  # Clear results for the next scan

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


# Export results to JSON
def export_results():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"dll_scan_results_{timestamp}.json"
    with open(output_file, "w") as f:
        json.dump(scan_results, f, indent=4)
    logging.info(f"Results exported to {output_file}")


# Main Function
if __name__ == "__main__":
    print("Choose an option:")
    print("1. Perform a one-time scan")
    print("2. Start real-time monitoring")
    choice = input("> ")

    if choice == "1":
        threads = []
        for proc in psutil.process_iter(['pid', 'name']):
            thread = threading.Thread(target=scan_process, args=(proc,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if scan_results:
            print("\nSuspicious DLLs detected:")
            for result in scan_results:
                print(f"Process: {result['name']} (PID: {result['pid']})")
                for dll in result['suspicious_dlls']:
                    print(f"  - {dll}")
            send_email_alert(scan_results)
            export_results()
        else:
            print("No suspicious DLLs detected.")
    elif choice == "2":
        real_time_monitor()
    else:
        print("Invalid choice. Exiting...")
