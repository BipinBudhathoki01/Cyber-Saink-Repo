import os
import sys
import platform
import requests
import zipfile
import tarfile
import shutil
import stat

# Constants
NUCLEI_VERSION = "3.2.0"
BASE_URL = f"https://github.com/projectdiscovery/nuclei/releases/download/v{NUCLEI_VERSION}/"

def get_nuclei_download_url():
    """Determines the correct Nuclei download URL for the current OS/Arch."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        return f"{BASE_URL}nuclei_{NUCLEI_VERSION}_windows_amd64.zip"
    elif system == "linux":
        if "aarch64" in machine or "arm64" in machine:
            return f"{BASE_URL}nuclei_{NUCLEI_VERSION}_linux_arm64.zip"
        else:
            return f"{BASE_URL}nuclei_{NUCLEI_VERSION}_linux_amd64.zip"
    elif system == "darwin": # MacOS
        if "arm64" in machine:
            return f"{BASE_URL}nuclei_{NUCLEI_VERSION}_macOS_arm64.zip"
        else:
            return f"{BASE_URL}nuclei_{NUCLEI_VERSION}_macOS_amd64.zip"
    return None

def get_nuclei_path():
    """Returns the expected path to the Nuclei binary."""
    base_dir = os.getcwd()
    binary_name = "nuclei.exe" if platform.system() == "Windows" else "nuclei"
    return os.path.join(base_dir, binary_name)

def is_nuclei_installed():
    """Checks if Nuclei is found at the local path or in system PATH."""
    # Check local path first
    if os.path.exists(get_nuclei_path()):
        return True
    # Check system path
    if shutil.which("nuclei"):
        return True
    return False

def download_and_extract_nuclei():
    """Downloads and extracts Nuclei binary."""
    url = get_nuclei_download_url()
    if not url:
        print("[-] Unsupported OS/Architecture for auto-download.")
        return False

    print(f"[+] Downloading Nuclei v{NUCLEI_VERSION}...")
    filename = url.split("/")[-1]
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        downloaded = 0

        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=block_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    # Simple progress
                    done = int(50 * downloaded / total_size) if total_size else 0
                    sys.stdout.write(f"\rDownloading: [{'=' * done}{' ' * (50-done)}] {downloaded//1024//1024}MB")
                    sys.stdout.flush()
        
        print("\n[+] Download complete. Extracting...")
        
        if filename.endswith(".zip"):
            with zipfile.ZipFile(filename, 'r') as zip_ref:
                zip_ref.extractall(".")
        elif filename.endswith(".tar.gz"):
            with tarfile.open(filename, "r:gz") as tar_ref:
                tar_ref.extractall(".")

        # Cleanup archive
        os.remove(filename)
        
        # Make executable on Linux/Mac
        binary_path = get_nuclei_path()
        if platform.system() != "Windows" and os.path.exists(binary_path):
            st = os.stat(binary_path)
            os.chmod(binary_path, st.st_mode | stat.S_IEXEC)
            
        print("[+] Nuclei installed successfully.")
        return True

    except Exception as e:
        print(f"[-] Error installing Nuclei: {e}")
        return False
