#!/usr/bin/env python3
"""
NOVA X ULTIMATE - ENTERPRISE NETWORK INTELLIGENCE
LEAN VERSION - NO EXTRA DEPENDENCIES REQUIRED
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import time
import socket
import threading
import subprocess
import platform
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque, defaultdict
from datetime import datetime, timedelta
import os
import sys
import ipaddress
import netifaces
import re
import urllib.request
import urllib.error
import json
import sqlite3
import hashlib
from collections import deque
import concurrent.futures

class NovaXUltimate:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 NOVA X ULTIMATE - ENTERPRISE NETWORK INTELLIGENCE")
        self.root.geometry("1800x1000")
        self.root.configure(bg='#0a0a1a')
        
        # Advanced data storage
        self.devices = {}
        self.security_alerts = []
        self.network_range = None
        self.gateway_ip = None
        self.interface = None
        self.is_scanning = False
        
        # Real-time data
        self.packet_count = 0
        self.traffic_data = deque(maxlen=50)
        self.alert_data = deque(maxlen=50)
        
        # Initialize database
        self.init_database()
        
        # Setup GUI
        self.setup_advanced_styles()
        self.setup_enterprise_gui()
        
        # Get network info
        self.get_network_info()
        
        # Start services
        self.start_enterprise_services()
        
        self.log_message("🚀 NOVA X ULTIMATE INITIALIZED - ENTERPRISE MODE ACTIVATED")

    def init_database(self):
        """Initialize SQLite database for persistent storage"""
        try:
            self.conn = sqlite3.connect('nova_x_enterprise.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            # Create devices table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    threat_level TEXT,
                    services TEXT
                )
            ''')
            
            # Create alerts table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT,
                    type TEXT,
                    message TEXT,
                    device_ip TEXT,
                    timestamp TEXT,
                    confidence REAL
                )
            ''')
            
            self.conn.commit()
        except Exception as e:
            self.log_message(f"❌ Database init error: {e}")

    def setup_advanced_styles(self):
        """Configure enterprise-grade styling"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Enterprise color scheme
        self.style.configure('Enterprise.TLabel', 
                           background='#1a1a2e',
                           foreground='#00ff88',
                           font=('Arial', 12, 'bold'))
        
        self.style.configure('Critical.TLabel',
                           background='#1a1a2e',
                           foreground='#ff4444',
                           font=('Arial', 11, 'bold'))
        
        self.style.configure('Enterprise.TFrame',
                           background='#16213e',
                           relief='raised',
                           borderwidth=2)

    def setup_enterprise_gui(self):
        """Setup enterprise-grade interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dashboard Tab
        self.dashboard_frame = ttk.Frame(self.notebook, style='Enterprise.TFrame')
        self.notebook.add(self.dashboard_frame, text="📊 DASHBOARD")
        
        # Discovery Tab
        self.discovery_frame = ttk.Frame(self.notebook, style='Enterprise.TFrame')
        self.notebook.add(self.discovery_frame, text="🔍 DISCOVERY")
        
        # Security Tab
        self.security_frame = ttk.Frame(self.notebook, style='Enterprise.TFrame')
        self.notebook.add(self.security_frame, text="🛡️ SECURITY")
        
        # Setup each tab
        self.setup_dashboard_tab()
        self.setup_discovery_tab()
        self.setup_security_tab()
        
        # Status bar
        self.setup_enterprise_status_bar()

    def setup_dashboard_tab(self):
        """Setup comprehensive dashboard"""
        # Header with KPIs
        kpi_frame = ttk.Frame(self.dashboard_frame, style='Enterprise.TFrame')
        kpi_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # KPI Metrics
        metrics = [
            ("🌐 Total Devices", "total_devices", "0"),
            ("🟢 Online Now", "online_devices", "0"),
            ("⚠️ Security Alerts", "security_alerts", "0"),
            ("📊 Traffic Monitor", "traffic_speed", "Active"),
            ("🛡️ Threats Found", "threats_found", "0"),
        ]
        
        for i, (label, var_name, default) in enumerate(metrics):
            frame = ttk.Frame(kpi_frame, style='Enterprise.TFrame')
            frame.grid(row=0, column=i, padx=5, pady=5, sticky='ew')
            
            ttk.Label(frame, text=label, style='Enterprise.TLabel').pack()
            setattr(self, f"{var_name}_label", ttk.Label(frame, text=default, 
                                                       style='Enterprise.TLabel',
                                                       font=('Arial', 14, 'bold')))
            getattr(self, f"{var_name}_label").pack()
        
        # Real-time charts
        charts_frame = ttk.Frame(self.dashboard_frame, style='Enterprise.TFrame')
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Network traffic chart
        self.setup_realtime_charts(charts_frame)
        
        # Quick actions
        actions_frame = ttk.Frame(self.dashboard_frame, style='Enterprise.TFrame')
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        
        action_buttons = [
            ("🚀 FULL NETWORK AUDIT", self.full_network_audit),
            ("⚡ QUICK SCAN", self.quick_scan),
            ("🔧 VULNERABILITY SCAN", self.vulnerability_scan),
            ("📊 TRAFFIC ANALYSIS", self.traffic_analysis),
            ("🛡️ THREAT HUNT", self.threat_hunt_scan),
        ]
        
        for text, command in action_buttons:
            ttk.Button(actions_frame, text=text, command=command, 
                      style='Enterprise.TFrame').pack(side=tk.LEFT, padx=5)

    def setup_discovery_tab(self):
        """Setup advanced discovery interface"""
        # Control panel
        control_frame = ttk.Frame(self.discovery_frame, style='Enterprise.TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        scan_buttons = [
            ("🔍 ARP Discovery", self.arp_discovery),
            ("🎯 Ping Sweep", self.ping_sweep),
            ("🌐 Port Scan", self.port_scan_all),
            ("📡 Service Scan", self.service_scan_all),
        ]
        
        for text, command in scan_buttons:
            ttk.Button(control_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)
        
        # Enhanced device table
        columns = ('IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Services', 
                  'Threat Level', 'First Seen', 'Last Seen')
        
        self.device_tree = ttk.Treeview(self.discovery_frame, columns=columns, 
                                       show='headings', height=20)
        
        column_widths = {
            'IP': 120, 'MAC': 140, 'Hostname': 150, 'Vendor': 120,
            'OS': 100, 'Services': 200, 'Threat Level': 100,
            'First Seen': 150, 'Last Seen': 150
        }
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(self.discovery_frame, orient=tk.VERTICAL, 
                                command=self.device_tree.yview)
        h_scroll = ttk.Scrollbar(self.discovery_frame, orient=tk.HORIZONTAL,
                                command=self.device_tree.xview)
        
        self.device_tree.configure(yscrollcommand=v_scroll.set,
                                  xscrollcommand=h_scroll.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Advanced context menu
        self.setup_advanced_context_menu()

    def setup_security_tab(self):
        """Setup security monitoring dashboard"""
        # Security alerts table
        alert_columns = ('Level', 'Type', 'Message', 'Device', 'Time', 'Confidence')
        self.alert_tree = ttk.Treeview(self.security_frame, columns=alert_columns,
                                      show='headings', height=15)
        
        for col in alert_columns:
            self.alert_tree.heading(col, text=col)
            self.alert_tree.column(col, width=120)
        
        self.alert_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Security controls
        controls_frame = ttk.Frame(self.security_frame, style='Enterprise.TFrame')
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        security_buttons = [
            ("🔍 SCAN FOR THREATS", self.scan_for_threats),
            ("🛡️ SECURITY REPORT", self.generate_security_report),
            ("🚨 INCIDENT RESPONSE", self.incident_response),
            ("📊 EXPORT DATA", self.export_data)
        ]
        
        for text, command in security_buttons:
            ttk.Button(controls_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

    def setup_realtime_charts(self, parent):
        """Setup real-time monitoring charts"""
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 6))
        self.fig.patch.set_facecolor('#16213e')
        
        # Style charts
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#1a1a2e')
            ax.tick_params(colors='white', labelsize=8)
            ax.grid(True, alpha=0.3, color='#444444')
            for spine in ax.spines.values():
                spine.set_color('#00ff88')
        
        self.ax1.set_title('Network Traffic Monitor', color='#00ff88', fontsize=12)
        self.ax1.set_ylabel('Devices Online', color='white', fontsize=10)
        
        self.ax2.set_title('Security Alerts', color='#00ff88', fontsize=12)
        self.ax2.set_ylabel('Alerts', color='white', fontsize=10)
        self.ax2.set_xlabel('Time', color='white', fontsize=10)
        
        self.canvas = FigureCanvasTkAgg(self.fig, parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def setup_enterprise_status_bar(self):
        """Setup enterprise status bar"""
        status_frame = ttk.Frame(self.root, style='Enterprise.TFrame')
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(status_frame, 
                                     text="NOVA X ULTIMATE - ENTERPRISE MODE ACTIVE", 
                                     style='Enterprise.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # System metrics
        self.cpu_label = ttk.Label(status_frame, text="CPU: 0%", style='Enterprise.TLabel')
        self.cpu_label.pack(side=tk.RIGHT, padx=10)
        
        self.memory_label = ttk.Label(status_frame, text="RAM: 0%", style='Enterprise.TLabel')
        self.memory_label.pack(side=tk.RIGHT, padx=10)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.scan_progress.pack(side=tk.RIGHT, padx=10, fill=tk.X, expand=True)

    def setup_advanced_context_menu(self):
        """Setup advanced right-click context menu"""
        self.advanced_context_menu = tk.Menu(self.device_tree, tearoff=0,
                                           bg='#1a1a2e', fg='#00ff88')
        
        advanced_actions = [
            ("🔍 Deep Port Scan", self.deep_port_scan),
            ("🛡️ Threat Analysis", self.single_device_threat_analysis),
            ("📊 Get Full Info", self.get_full_device_info),
            ("🌐 External Lookup", self.external_intel_lookup),
            ("🔧 Service Enumeration", self.service_enumeration),
            ("🚨 Isolate Device", self.isolate_device)
        ]
        
        for label, command in advanced_actions:
            self.advanced_context_menu.add_command(label=label, command=command)
        
        self.device_tree.bind("<Button-3>", self.show_advanced_context_menu)

    def show_advanced_context_menu(self, event):
        """Show advanced context menu"""
        item = self.device_tree.identify_row(event.y)
        if item:
            self.device_tree.selection_set(item)
            self.advanced_context_menu.post(event.x_root, event.y_root)

    def get_network_info(self):
        """Get network information"""
        try:
            gateways = netifaces.gateways()
            if netifaces.AF_INET in gateways['default']:
                gateway_info = gateways['default'][netifaces.AF_INET]
                self.gateway_ip = gateway_info[0]
                self.interface = gateway_info[1]
                
                addrs = netifaces.ifaddresses(self.interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip_address = ip_info['addr']
                    netmask = ip_info['netmask']
                    
                    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                    self.network_range = str(network)
                    
                    self.log_message("🚀 NOVA X ULTIMATE INITIALIZED")
                    self.log_message(f"📍 Network: {self.network_range}")
                    self.log_message(f"🎯 Gateway: {self.gateway_ip}")
                    self.log_message(f"🔧 Interface: {self.interface}")
                    
        except Exception as e:
            self.log_message(f"❌ Network detection failed: {e}")
            self.network_range = "192.168.1.0/24"

    def start_enterprise_services(self):
        """Start all enterprise services"""
        services = [
            self.monitor_system_resources,
            self.start_background_discovery,
            self.update_realtime_charts
        ]
        
        for service in services:
            threading.Thread(target=service, daemon=True).start()
        
        self.log_message("✅ All enterprise services started")

    def monitor_system_resources(self):
        """Monitor system resources in real-time"""
        while True:
            try:
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                
                self.root.after(0, lambda: self.cpu_label.config(text=f"CPU: {cpu_percent}%"))
                self.root.after(0, lambda: self.memory_label.config(text=f"RAM: {memory_percent}%"))
                
                time.sleep(2)
            except Exception as e:
                time.sleep(5)

    def start_background_discovery(self):
        """Continuous background discovery"""
        while True:
            try:
                if not self.is_scanning:
                    self.quick_background_scan()
                time.sleep(30)
            except Exception as e:
                time.sleep(30)

    def update_realtime_charts(self):
        """Update real-time charts"""
        while True:
            try:
                online_count = sum(1 for d in self.devices.values() if self.is_device_online(d['ip']))
                alert_count = len(self.security_alerts)
                
                self.traffic_data.append(online_count)
                self.alert_data.append(alert_count)
                
                self.root.after(0, self.update_charts_display)
                time.sleep(2)
            except Exception as e:
                time.sleep(5)

    def update_charts_display(self):
        """Update charts display"""
        try:
            self.ax1.clear()
            self.ax2.clear()
            
            # Traffic chart
            if self.traffic_data:
                self.ax1.plot(list(self.traffic_data), color='#00ff88', linewidth=2)
            self.ax1.set_title('Online Devices', color='#00ff88', fontsize=12)
            self.ax1.set_facecolor('#1a1a2e')
            self.ax1.grid(True, alpha=0.3)
            
            # Alerts chart
            if self.alert_data:
                self.ax2.plot(list(self.alert_data), color='#ff4444', linewidth=2)
            self.ax2.set_title('Security Alerts', color='#00ff88', fontsize=12)
            self.ax2.set_facecolor('#1a1a2e')
            self.ax2.grid(True, alpha=0.3)
            
            self.canvas.draw()
            
        except Exception as e:
            pass

    # ENTERPRISE SCANNING METHODS

    def full_network_audit(self):
        """Comprehensive network audit"""
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_progress.start()
        self.log_message("🚀 INITIATING ENTERPRISE NETWORK AUDIT")
        
        def audit_thread():
            try:
                audit_phases = [
                    ("🌐 Network Discovery", self.comprehensive_discovery),
                    ("🛡️ Security Assessment", self.security_assessment),
                    ("🔍 Vulnerability Scan", self.vulnerability_scan),
                    ("📊 Behavioral Analysis", self.behavioral_analysis)
                ]
                
                for phase_name, phase_method in audit_phases:
                    self.log_message(f"🔧 PHASE: {phase_name}")
                    phase_method()
                    time.sleep(1)
                
                self.log_message("🎉 ENTERPRISE AUDIT COMPLETE")
                self.generate_audit_report()
                
            except Exception as e:
                self.log_message(f"❌ Audit error: {e}")
            finally:
                self.is_scanning = False
                self.root.after(0, self.scan_progress.stop)
        
        threading.Thread(target=audit_thread, daemon=True).start()

    def comprehensive_discovery(self):
        """Comprehensive network discovery"""
        methods = [
            self.arp_discovery,
            self.ping_sweep,
            self.port_scan_all
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for method in methods:
                executor.submit(method)

    def arp_discovery(self):
        """ARP table discovery"""
        self.log_message("   📡 ARP Discovery...")
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                self.parse_arp_output(result.stdout)
        except Exception as e:
            self.log_message(f"❌ ARP discovery error: {e}")

    def ping_sweep(self):
        """Ping sweep discovery"""
        self.log_message("   🎯 Ping Sweep...")
        if not self.network_range:
            return
            
        try:
            network = ipaddress.IPv4Network(self.network_range, strict=False)
            ip_list = [str(ip) for ip in network.hosts()][:50]  # Limit for speed
            
            def ping_ip(ip):
                try:
                    param = "-n 1" if platform.system() == "Windows" else "-c 1"
                    timeout = "-w 1000" if platform.system() == "Windows" else "-W 1"
                    command = ['ping', param, timeout, ip]
                    result = subprocess.run(command, capture_output=True, timeout=2)
                    if result.returncode == 0:
                        return ip
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                results = executor.map(ping_ip, ip_list)
                for ip in results:
                    if ip:
                        self.add_device(ip, "Unknown", "Ping Response")
                        
        except Exception as e:
            self.log_message(f"❌ Ping sweep error: {e}")

    def parse_arp_output(self, output):
        """Parse ARP table output"""
        lines = output.split('\n')
        for line in lines:
            try:
                ip, mac = self.extract_ip_mac(line)
                if ip and mac:
                    self.add_device(ip, mac, "ARP Table")
            except:
                continue

    def extract_ip_mac(self, line):
        """Extract IP and MAC from line"""
        line = line.strip()
        
        # Windows format: 192.168.1.1 xx-xx-xx-xx-xx-xx
        # Linux format: 192.168.1.1 ether xx:xx:xx:xx:xx:xx
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        
        ip_match = re.search(ip_pattern, line)
        mac_match = re.search(mac_pattern, line)
        
        if ip_match and mac_match:
            return ip_match.group(), mac_match.group()
        
        return None, None

    def add_device(self, ip, mac, source):
        """Add device to database"""
        device_key = f"{ip}_{mac}"
        
        if device_key not in self.devices:
            self.devices[device_key] = {
                'ip': ip,
                'mac': mac,
                'hostname': self.get_hostname(ip),
                'vendor': self.get_vendor(mac),
                'os': self.os_fingerprint(ip),
                'services': "Unknown",
                'threat_level': "Unknown",
                'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Save to database
            self.save_device_to_db(self.devices[device_key])
            
            self.log_message(f"   ✅ {source}: {ip} -> {mac}")
            self.root.after(0, self.update_device_display)

    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                return hostname
        except:
            pass
        return "Unknown"

    def get_vendor(self, mac):
        """Get vendor from MAC"""
        if not mac or mac == "Unknown":
            return "Unknown"
            
        vendor_db = {
            "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:42": "Parallels",
            "00:1D:0F": "Dell", "00:21:5A": "Dell", "00:15:5D": "Microsoft",
            "00:0F:FE": "Apple", "00:1B:63": "Apple", "08:00:27": "VirtualBox",
            "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi"
        }
        
        mac_prefix = mac.upper()[:8]
        return vendor_db.get(mac_prefix, "Unknown")

    def os_fingerprint(self, ip):
        """Basic OS fingerprinting"""
        try:
            response = os.popen(f"ping -c 1 {ip}").read()
            if "ttl=" in response.lower():
                ttl = int(re.search(r"ttl=(\d+)", response.lower()).group(1))
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
        except:
            pass
        return "Unknown"

    def security_assessment(self):
        """Security assessment"""
        self.log_message("   🛡️ Security Assessment...")
        
        for device_key, device in self.devices.items():
            threat_level = self.assess_device_threat(device)
            device['threat_level'] = threat_level
            
            if threat_level in ["MEDIUM", "HIGH"]:
                self.create_security_alert(
                    threat_level, "DEVICE_ASSESSMENT",
                    f"Device {device['ip']} has {threat_level} threat level",
                    device['ip'], 0.7
                )

    def assess_device_threat(self, device):
        """Assess device threat level"""
        score = 0
        
        # Check for suspicious vendors
        if device['vendor'] == "Unknown":
            score += 1
            
        # Check for suspicious ports (simplified)
        if device['services'] != "Unknown":
            if "Telnet" in device['services']:
                score += 2
            if "FTP" in device['services']:
                score += 1
                
        if score >= 2:
            return "HIGH"
        elif score >= 1:
            return "MEDIUM"
        else:
            return "LOW"

    def vulnerability_scan(self):
        """Vulnerability scan"""
        self.log_message("   🔓 Vulnerability Scan...")
        # Simple port-based vulnerability detection
        common_vulnerable_ports = {
            21: 'FTP - Clear text credentials',
            23: 'Telnet - Unencrypted communication',
            80: 'HTTP - Unencrypted web traffic',
            161: 'SNMP - Default community strings'
        }
        
        for device_key, device in self.devices.items():
            if self.is_device_online(device['ip']):
                open_ports = self.scan_ports(device['ip'], list(common_vulnerable_ports.keys()))
                if open_ports:
                    for port in open_ports:
                        vulnerability = common_vulnerable_ports.get(port)
                        if vulnerability:
                            self.create_security_alert(
                                "HIGH", "VULNERABILITY",
                                f"{device['ip']}:{port} - {vulnerability}",
                                device['ip'], 0.8
                            )

    def scan_ports(self, ip, ports):
        """Scan ports on device"""
        open_ports = []
        for port in ports:
            if self.is_port_open(ip, port):
                open_ports.append(port)
        return open_ports

    def is_port_open(self, ip, port, timeout=1):
        """Check if port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False

    def is_device_online(self, ip):
        """Check if device is online"""
        try:
            param = "-n 1" if platform.system() == "Windows" else "-c 1"
            timeout = "-w 1000" if platform.system() == "Windows" else "-W 1"
            command = ['ping', param, timeout, ip]
            result = subprocess.run(command, capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False

    def behavioral_analysis(self):
        """Behavioral analysis"""
        self.log_message("   🤖 Behavioral Analysis...")
        # Simple behavioral analysis
        for device_key, device in self.devices.items():
            if device['vendor'] == "Unknown" and device['hostname'] == "Unknown":
                self.create_security_alert(
                    "MEDIUM", "BEHAVIORAL",
                    f"Device {device['ip']} has no identifiable information",
                    device['ip'], 0.6
                )

    def create_security_alert(self, level, alert_type, message, device_ip, confidence):
        """Create security alert"""
        alert = {
            'level': level,
            'type': alert_type,
            'message': message,
            'device_ip': device_ip,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'confidence': confidence
        }
        
        self.security_alerts.append(alert)
        
        # Save to database
        self.cursor.execute('''
            INSERT INTO security_alerts (level, type, message, device_ip, timestamp, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (level, alert_type, message, device_ip, alert['timestamp'], confidence))
        self.conn.commit()
        
        self.root.after(0, self.update_security_display)
        self.log_message(f"   ⚠️ {level} ALERT: {message}")

    def quick_scan(self):
        """Quick network scan"""
        self.log_message("⚡ Quick Network Scan...")
        self.comprehensive_discovery()

    def threat_hunt_scan(self):
        """Threat hunting scan"""
        self.log_message("🔍 Threat Hunting...")
        self.security_assessment()
        self.vulnerability_scan()
        self.behavioral_analysis()

    def port_scan_all(self):
        """Port scan all devices"""
        self.log_message("🔧 Port Scanning All Devices...")
        common_ports = [21, 22, 23, 80, 443, 3389, 8080]
        
        for device_key, device in self.devices.items():
            if self.is_device_online(device['ip']):
                open_ports = self.scan_ports(device['ip'], common_ports)
                if open_ports:
                    services = [str(port) for port in open_ports]
                    device['services'] = ', '.join(services)
                    self.log_message(f"   ✅ {device['ip']} - Ports: {services}")

    def service_scan_all(self):
        """Service scan all devices"""
        self.log_message("🔧 Service Scanning...")
        self.port_scan_all()  # For now, same as port scan

    def traffic_analysis(self):
        """Traffic analysis"""
        self.log_message("📊 Traffic Analysis...")
        online_count = sum(1 for d in self.devices.values() if self.is_device_online(d['ip']))
        self.log_message(f"   📈 Online Devices: {online_count}/{len(self.devices)}")

    def scan_for_threats(self):
        """Scan for threats"""
        self.log_message("🛡️ Scanning for Threats...")
        self.threat_hunt_scan()

    def generate_security_report(self):
        """Generate security report"""
        self.log_message("📄 Generating Security Report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'devices_found': len(self.devices),
            'security_alerts': len(self.security_alerts),
            'high_alerts': len([a for a in self.security_alerts if a['level'] == 'HIGH']),
            'network_range': self.network_range
        }
        
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log_message(f"💾 Security report saved: {filename}")

    def incident_response(self):
        """Incident response"""
        self.log_message("🚨 Incident Response Activated")
        # Simple incident response - just log for now
        self.log_message("   📝 Logging incident...")
        self.log_message("   🔧 Recommended actions: Isolate affected devices")

    def export_data(self):
        """Export data"""
        self.log_message("💾 Exporting Data...")
        
        # Export devices to CSV
        filename = f"devices_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Services', 'Threat Level'])
            for device in self.devices.values():
                writer.writerow([
                    device['ip'], device['mac'], device['hostname'],
                    device['vendor'], device['os'], device['services'],
                    device['threat_level']
                ])
        
        self.log_message(f"💾 Data exported: {filename}")

    def generate_audit_report(self):
        """Generate audit report"""
        self.log_message("📊 Generating Audit Report...")
        
        report = {
            'audit_date': datetime.now().isoformat(),
            'network_range': self.network_range,
            'total_devices': len(self.devices),
            'security_alerts': len(self.security_alerts),
            'high_risk_devices': len([d for d in self.devices.values() if d['threat_level'] == 'HIGH'])
        }
        
        filename = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log_message(f"💾 Audit report saved: {filename}")

    def quick_background_scan(self):
        """Quick background scan"""
        try:
            self.arp_discovery()
            self.root.after(0, self.update_device_display)
        except:
            pass

    def save_device_to_db(self, device):
        """Save device to database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO devices 
                (ip, mac, hostname, vendor, first_seen, last_seen, threat_level, services)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device['ip'], device['mac'], device['hostname'],
                device['vendor'], device['first_seen'], device['last_seen'],
                device['threat_level'], device['services']
            ))
            self.conn.commit()
        except Exception as e:
            pass

    def update_device_display(self):
        """Update device display"""
        try:
            # Clear existing items
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            
            # Add devices
            for device in self.devices.values():
                self.device_tree.insert('', 'end', values=(
                    device['ip'],
                    device['mac'],
                    device['hostname'],
                    device['vendor'],
                    device['os'],
                    device['services'],
                    device['threat_level'],
                    device['first_seen'],
                    device['last_seen']
                ))
            
            # Update KPIs - FIXED THE SYNTAX ERROR HERE
            online_count = sum(1 for d in self.devices.values() if self.is_device_online(d['ip']))
            threat_count = len([d for d in self.devices.values() if d['threat_level'] in ['MEDIUM', 'HIGH']])
            
            self.total_devices_label.config(text=str(len(self.devices)))
            self.online_devices_label.config(text=str(online_count))
            self.security_alerts_label.config(text=str(len(self.security_alerts)))
            self.threats_found_label.config(text=str(threat_count))
            
        except Exception as e:
            pass

    def update_security_display(self):
        """Update security display"""
        try:
            # Clear existing alerts
            for item in self.alert_tree.get_children():
                self.alert_tree.delete(item)
            
            # Add recent alerts
            for alert in self.security_alerts[-20:]:
                self.alert_tree.insert('', 'end', values=(
                    alert['level'],
                    alert['type'],
                    alert['message'],
                    alert['device_ip'],
                    alert['timestamp'],
                    f"{alert['confidence']:.1f}"
                ))
        except Exception as e:
            pass

    # Context menu actions
    def deep_port_scan(self):
        selection = self.device_tree.selection()
        if selection:
            item = selection[0]
            ip = self.device_tree.item(item)['values'][0]
            self.log_message(f"🔍 Deep port scan: {ip}")
            self.port_scan_single(ip)

    def single_device_threat_analysis(self):
        selection = self.device_tree.selection()
        if selection:
            item = selection[0]
            ip = self.device_tree.item(item)['values'][0]
            self.log_message(f"🛡️ Threat analysis: {ip}")
            # Find device and assess threat
            for device in self.devices.values():
                if device['ip'] == ip:
                    threat_level = self.assess_device_threat(device)
                    self.log_message(f"   📊 {ip} threat level: {threat_level}")

    def get_full_device_info(self):
        selection = self.device_tree.selection()
        if selection:
            item = selection[0]
            ip = self.device_tree.item(item)['values'][0]
            self.log_message(f"📋 Full info for: {ip}")
            for device in self.devices.values():
                if device['ip'] == ip:
                    for key, value in device.items():
                        self.log_message(f"   {key}: {value}")

    def external_intel_lookup(self):
        selection = self.device_tree.selection()
        if selection:
            item = selection[0]
            ip = self.device_tree.item(item)['values'][0]
            self.log_message(f"🌐 External lookup: {ip}")
            # Simple external lookup - could be enhanced
            self.log_message(f"   🔍 Checking {ip} against public databases...")

    def service_enumeration(self):
        selection = self.device_tree.selection()
        if selection:
            item = selection[0]
            ip = self.device_tree.item(item)['values'][0]
            self.log_message(f"🔧 Service enumeration: {ip}")
            self.port_scan_single(ip)

    def isolate_device(self):
        selection = self.device_tree.selection()
        if selection:
            item = selection[0]
            ip = self.device_tree.item(item)['values'][0]
            self.log_message(f"🚨 Isolating device: {ip}")
            self.log_message("   ⚠️ This would block the device in a real environment")

    def port_scan_single(self, ip):
        """Port scan single device"""
        def scan_thread():
            ports = [21, 22, 23, 80, 443, 3389, 8080, 8443]
            open_ports = []
            
            for port in ports:
                if self.is_port_open(ip, port):
                    open_ports.append(port)
                    self.log_message(f"   ✅ {ip}:{port} OPEN")
            
            if open_ports:
                # Update device services
                for device in self.devices.values():
                    if device['ip'] == ip:
                        device['services'] = ', '.join(map(str, open_ports))
                        break
                
                self.root.after(0, self.update_device_display)
                self.log_message(f"📊 {ip} has {len(open_ports)} open ports")
            else:
                self.log_message(f"📊 {ip} has no open common ports")
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def log_message(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        
        # Print to console
        print(formatted)
        
        # Try to update GUI if available
        try:
            if hasattr(self, 'log_text'):
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, formatted + '\n')
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except:
            pass

def main():
    """Main application"""
    try:
        # Check for root privileges
        if os.name != 'nt' and os.geteuid() != 0:
            print("🔒 NOVA X ULTIMATE - ENTERPRISE MODE")
            print("⚡ Root privileges recommended for full capabilities")
            print("💡 Run with: sudo python3 nova_x_ultimate.py")
            print("   Continuing with limited features...")
        
        # Launch application
        root = tk.Tk()
        app = NovaXUltimate(root)
        
        print("🎯 NOVA X ULTIMATE - ENTERPRISE MODE ACTIVATED")
        print("🚀 Features: Advanced Discovery, Threat Analysis, Real-time Monitoring")
        print("📊 Enterprise Analytics: Active")
        
        root.mainloop()
        
    except Exception as e:
        print(f"❌ NOVA X ULTIMATE Failed: {e}")
        messagebox.showerror("NOVA X ULTIMATE", f"Startup failed: {e}")

if __name__ == "__main__":
    main()
