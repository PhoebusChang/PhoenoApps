import tkinter as tk
import tkinter.ttk as ttk
import requests
import ctypes
import time
from PIL import Image, ImageTk
import webbrowser
import subprocess
import sys
import zipfile
import os
from urllib.request import urlopen


# Define the server URL where the latest version is hosted
UPDATE_SERVER_URL = 'https://phoeno.xyz/applications/fhjh-wifi-login-pro/'

# Current version of your application
CURRENT_VERSION = '1.0'


def read_online_text_file(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception if the request was unsuccessful

        # Assuming the text encoding is UTF-8. Adjust if you expect a different encoding.
        text_content = response.text

        return text_content
    except requests.exceptions.RequestException as e:
        print("Error occurred:", e)
        return text_content

def show_alert(title, message):
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x0 | 0x40)

def check_for_updates():
    try:
        vurl = "https://phoeno.xyz/applications/fhjh-wifi-login-pro/version.txt"
        print(read_online_text_file(vurl))
        if str(read_online_text_file(vurl)) != str(CURRENT_VERSION):
            print(f"{read_online_text_file(vurl)} is not {CURRENT_VERSION}")
            show_alert("Phoeno Alert", 'An update is available! Downloading installation file, this might take a while')
            download_update()
        else:
            show_alert("Phoeno Alert", 'No updates available.')

    except requests.RequestException:
        show_alert("Phoeno Alert", 'Failed to check for updates.')

def download_update():
    url = UPDATE_SERVER_URL + 'fhjh_login_pro_setup.exe'
    try:
        with requests.get(url, stream=True) as response:
            if response.status_code == 200:
                with open("fhjh_login_pro_setup.exe", 'wb') as file:
                    chunk_size = 8192
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if chunk:
                            file.write(chunk)
                            
                show_alert("Phoeno Alert", 'Download Complete, installation file will run')
            else:
                show_alert("Phoeno Alert", f"Error: Received status code {response.status_code} for URL: {url}")
    except requests.RequestException as e:
        show_alert("Phoeno Alert", 'Failed to download update.')


    install_update()


def install_update():
    try:
        
        os.startfile("fhjh_login_pro_setup.exe")

        print("External executable opened successfully.")
        
        sys.exit()



    except Exception as e:
        show_alert("Phoeno Alert", f'Error installing update: {str(e)}')

def animate_label(label):
    fg_colors = ['#FF0000', '#FFA500', '#FFFF00', '#00FF00', '#0000FF', '#800080']
    bg_colors = ['#000000'] * len(fg_colors)
    delay = 100

    for fg_color, bg_color in zip(fg_colors, bg_colors):
        label.config(foreground=fg_color, background=bg_color)
        label.update()
        time.sleep(delay / 1000)

def send_post_request(url, data, headers=None):
    response = requests.post(url, data=data, headers=headers, allow_redirects=True)
    return response

def on_submit():
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        ctypes.windll.user32.MessageBoxW(0, "Please enter both username and password.", "Fhjh wifi login PRO By Phoeno", 0x40 | 0x1)
        return

    url = 'http://192.168.50.253/loginpages/userlogin.shtml'
    data = {
        'username': username,
        'password': password,
        'vlan_id': '0'
    }
    headers = {
        'Host': '192.168.50.253',
        'Content-Length': '35',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'http://192.168.50.253',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Referer': 'http://192.168.50.253/loginpages/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': 'Session=56c37caf6b0c991b8ec2c66054b97ad2',
        'Connection': 'close'
    }

    response = send_post_request(url, data, headers)
    print(f"Response status code: {response.status_code}")
    print(f"Response content: {response.headers}")
    location_header = response.headers.get('Transfer-Encoding')
    
    if location_header is not None:
        if "chunked" in location_header:
            print("SUCCESS")
            ctypes.windll.user32.MessageBoxW(0, "SUCCESS", "Fhjh wifi login PRO By Phoeno", 0x40 | 0x1)
            webbrowser.get("chrome").open_new_tab("https://phoeno.xyz")
        else:
            print("FAILED")
            ctypes.windll.user32.MessageBoxW(0, "FAILED", "Fhjh wifi login PRO By Phoeno", 0x40 | 0x1)
    else:
        print("FAILED")
        ctypes.windll.user32.MessageBoxW(0, "FAILED", "Fhjh wifi login PRO By Phoeno", 0x40 | 0x1)

    check_for_updates()
# Call the check_for_updates function to check for updates


# Create tkinter window
window = tk.Tk()
window.title("Fhjh wifi login PRO By Phoeno")
window.geometry("600x400")
window.configure(background='black')


# Create style for transparent label
style = ttk.Style()
style.configure('Transparent.TLabel', background='#000000', foreground='#FFFFFF')


# Load and resize the logo image
logo_image = Image.open('logo_frame_1.png')
logo_image = logo_image.resize((150, 150), Image.ANTIALIAS)
logo_photo = ImageTk.PhotoImage(logo_image)

# Create logo label with rounded corners
logo_label = ttk.Label(window, image=logo_photo, style='Transparent.TLabel')
logo_label.image = logo_photo
logo_label.pack(pady=20)

# Create username label and entry
username_label = ttk.Label(window, text="Username:", style='Transparent.TLabel')
username_label.pack(pady=10)
username_entry = ttk.Entry(window)
username_entry.pack(pady=5)

# Create password label and entry
password_label = ttk.Label(window, text="Password:", style='Transparent.TLabel')
password_label.pack(pady=10)
password_entry = ttk.Entry(window, show="*")
password_entry.pack(pady=5)


# Create submit button
submit_button = ttk.Button(window, text="Submit", command=on_submit)
submit_button.pack()

update_button = ttk.Button(window, text="Check For UPDATE!", command= check_for_updates)
update_button.pack(side = "bottom")

# Bind Enter key to submit button
window.bind('<Return>', lambda event: submit_button.invoke())

# Animate label when window is clicked
username_label.bind('<Button-1>', lambda event: animate_label(username_label))

# Start the tkinter event loop
window.mainloop()
