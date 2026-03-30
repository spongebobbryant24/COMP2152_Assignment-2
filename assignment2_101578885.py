"""
Author: Jamshaid Mirpour
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime


print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Store common port numbers and their associated services for lookup during scanning
common_ports = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows the program to 
    # control access to the target attribute. This is a better decision than 
    # allowing direct access to the attribute because it allows us to add validation logic.
    # In this program, the setter checks if the new value is not an empty string 
    # before updating the target.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty.")
        

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses code from NetworkTools by inheriting the target attribute and its getter/setter methods.
# This helps to avoid code duplication in the child class.
# For example, the PortScanner class uses super().__init__(target) to call the parent constructor and 
# initialize the target attribute.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # What would happen without the try-except block is that the program can crash if an error occurs.
        # For example, if there is a network issue, the connection attempt could raise errors and stop scanning.
        # Using the try-except block helps the scanner to run and report the problem safely.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0: 
                status = "Open" 
            else: 
                status = "Closed"
            
            service_name = common_ports.get(port, "Unknown")
            
            self.lock.acquire()
            try:
                self.scan_results.append((port, status, service_name))
            finally:
                self.lock.release()

        except socket.error as e:
            print(f"Socket error on port {port}: {e}")
        finally:
            if sock is not None:    
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # We use threading to scan multiple ports because it allows the scan to run concurrently,
    # which increases the speed of the scan significantly. 
    # Scanning one port at a time can be very slow, especially if there are many ports to scan or 
    # if some ports have long timeouts. 
    # Threading allows us to initiate multiple scans simultaneously, reducing the overall time taken 
    # to complete the scan.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
        
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

def save_results(target, results):
    try:    
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        ''')
    
        for port, status, service in results:
            cursor.execute('''
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, port, status, service, datetime.datetime.now().isoformat()))
    
        conn.commit()
        conn.close()
    
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if rows:
            for row in rows:
                target, port, status, service, scan_date = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        else:
            print("No past scans found.")
        conn.close()
    
    except sqlite3.Error:
        print("No past scans found.")

def get_valid_port(prompt, start_port=None):
    while True:
        try:
            port = int(input(prompt))

            if port < 1 or port > 1024:
                print("Port must be between 1 and 1024.")
                continue

            if start_port is not None and port < start_port:
                print("End port must be greater than or equal to start port.")
                continue

            return port

        except ValueError:
            print("Invalid input. Please enter a valid integer.")


if __name__ == "__main__":
    target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    start_port = get_valid_port("Enter starting port number (1-1024): ")
    end_port = get_valid_port("Enter ending port number (1-1024): ", start_port)

    scanner = PortScanner(target)

    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if choice == "yes":
        load_past_scans()




# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    pass


# Q5: New Feature Proposal
# A feature I would like to add to this port scanner is a risk classifier that helps label open ports as high-risk, 
# medium-risk, or low-risk. I would use a nested if-statement to check each open port and assign a risk level it is commonly associated with.
# Diagram: Check diagram_101578885.png in the repository root
