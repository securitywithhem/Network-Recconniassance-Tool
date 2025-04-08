import re
import subprocess
import socket
import ipaddress
from datetime import datetime
import concurrent.futures
import time
import os
import platform
import urllib.request
import tempfile

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the header of the program"""
    clear_screen()
    print("""
╔════════════════════════════════════════════════════════════════╗
║                 NETWORK RECONNAISSANCE TOOL                    ║
║                                                               ║
║  A comprehensive tool for network analysis and scanning       ║
╚════════════════════════════════════════════════════════════════╝
""")

def print_progress(message):
    """Print progress message with timestamp"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {message}")

def validate_ip(ip):
    """Validate IP address format"""
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False, ["Invalid IP format"]
    
    try:
        ipaddress.ip_address(ip)
        return True, []
    except ValueError:
        return False, ["Invalid IP address"]

def show_menu():
    """Display the main menu"""
    print("\nAvailable Scanning Options:")
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║ 1. Quick Nmap Scan (Basic port scan)                          ║")
    print("║ 2. Detailed Port Analysis (TCP/UDP)                           ║")
    print("║ 3. DNS Analysis                                               ║")
    print("║ 4. Network Topology (Traceroute)                              ║")
    print("║ 5. Run All Scans                                              ║")
    print("║ 0. Exit                                                       ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    
    while True:
        try:
            choice = int(input("\nEnter your choice (0-5): "))
            if 0 <= choice <= 5:
                return choice
            print("Please enter a number between 0 and 5")
        except ValueError:
            print("Please enter a valid number")

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def check_and_install_nmap():
    """Check if nmap is installed and offer to install it if not"""
    try:
        # Check if nmap is installed
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        print("\nNmap is not installed on your system.")
        install_choice = input("Would you like to install nmap now? (y/n): ").lower()
        
        if install_choice != 'y':
            print("Nmap is required for network scanning. Please install it manually.")
            return False
        
        try:
            system = platform.system().lower()
            if system == 'windows':
                if not is_admin():
                    print("Administrator privileges are required to install nmap on Windows.")
                    print("Please run this script as administrator.")
                    return False
                
                print_progress("Installing nmap on Windows...")
                # Download nmap installer
                temp_dir = tempfile.mkdtemp()
                installer_path = os.path.join(temp_dir, 'nmap-installer.exe')
                
                print_progress("Downloading nmap installer...")
                urllib.request.urlretrieve('https://nmap.org/dist/nmap-7.94-setup.exe', installer_path)
                
                print_progress("Running nmap installer...")
                subprocess.run([installer_path, '/S'], check=True)
                
                # Add nmap to PATH
                nmap_path = r'C:\Program Files (x86)\Nmap'
                if not os.path.exists(nmap_path):
                    nmap_path = r'C:\Program Files\Nmap'
                
                if os.path.exists(nmap_path):
                    os.environ['PATH'] = f"{os.environ['PATH']};{nmap_path}"
                    print_progress("Nmap installed successfully!")
                    return True
                else:
                    print("Nmap installation path not found. Please add nmap to your PATH manually.")
                    return False
                
            elif system == 'darwin':  # macOS
                print_progress("Installing nmap using Homebrew...")
                subprocess.run(['brew', 'install', 'nmap'], check=True)
            elif system == 'linux':
                # Try to detect package manager
                if os.path.exists('/usr/bin/apt-get'):
                    print_progress("Installing nmap using apt...")
                    subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                    subprocess.run(['sudo', 'apt-get', 'install', '-y', 'nmap'], check=True)
                elif os.path.exists('/usr/bin/yum'):
                    print_progress("Installing nmap using yum...")
                    subprocess.run(['sudo', 'yum', 'install', '-y', 'nmap'], check=True)
                elif os.path.exists('/usr/bin/dnf'):
                    print_progress("Installing nmap using dnf...")
                    subprocess.run(['sudo', 'dnf', 'install', '-y', 'nmap'], check=True)
                else:
                    print("Could not determine package manager. Please install nmap manually.")
                    return False
            else:
                print("Unsupported operating system. Please install nmap manually.")
                return False
            
            print_progress("Nmap installed successfully!")
            return True
        except subprocess.SubprocessError as e:
            print(f"Error installing nmap: {str(e)}")
            print("Please install nmap manually.")
            return False
        except Exception as e:
            print(f"Unexpected error during nmap installation: {str(e)}")
            return False

def perform_quick_nmap_scan(ip):
    """Perform quick nmap scan with essential information"""
    try:
        print_progress("Starting quick nmap scan...")
        
        # Check if nmap is installed and offer to install if not
        if not check_and_install_nmap():
            return "Nmap is required for scanning. Please install it and try again."
        
        # Adjust command based on OS
        if platform.system().lower() == 'windows':
            nmap_cmd = ['nmap.exe']
        else:
            nmap_cmd = ['nmap']
        
        # Quick scan with common ports and no ping
        result = subprocess.run(nmap_cmd + ['-Pn', '-sS', '-T4', '-F', '--max-retries', '3', '--host-timeout', '30s', ip], 
                              capture_output=True, 
                              text=True)
        
        if result.returncode != 0:
            return f"Nmap scan failed with error code {result.returncode}\nError output: {result.stderr}"
        
        if not result.stdout.strip():
            return "Nmap scan completed but no results were returned. The target might be blocking scans."
        
        print_progress("Quick nmap scan completed")
        return result.stdout
    except Exception as e:
        return f"Nmap scan failed: {str(e)}"

def analyze_ports(ip):
    """Analyze TCP and UDP ports in parallel"""
    try:
        print_progress("Starting port analysis...")
        
        # Check if nmap is installed and offer to install if not
        if not check_and_install_nmap():
            return "Nmap is required for port analysis. Please install it and try again."
        
        # Adjust command based on OS
        if platform.system().lower() == 'windows':
            nmap_cmd = ['nmap.exe']
        else:
            nmap_cmd = ['nmap']
        
        def run_tcp_scan():
            return subprocess.run(nmap_cmd + ['-Pn', '-sS', '-T4', '-p1-1024', '--max-retries', '3', '--host-timeout', '30s', ip], 
                                capture_output=True, 
                                text=True)
        
        def run_udp_scan():
            return subprocess.run(nmap_cmd + ['-Pn', '-sU', '-T4', '-p53,67,68,69,123,161,162', '--max-retries', '3', '--host-timeout', '30s', ip], 
                                capture_output=True, 
                                text=True)
        
        # Run TCP and UDP scans in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            tcp_future = executor.submit(run_tcp_scan)
            udp_future = executor.submit(run_udp_scan)
            
            tcp_scan = tcp_future.result()
            udp_scan = udp_future.result()
        
        if tcp_scan.returncode != 0:
            return f"TCP port scan failed with error code {tcp_scan.returncode}\nError output: {tcp_scan.stderr}"
        
        print_progress("TCP port scan completed")
        
        if udp_scan.returncode != 0:
            return f"UDP port scan failed with error code {udp_scan.returncode}\nError output: {udp_scan.stderr}"
        
        print_progress("UDP port scan completed")
        
        # Format the output
        output = ["Port Analysis Results:"]
        output.append("\nTCP Port Analysis:")
        output.append(tcp_scan.stdout if tcp_scan.stdout.strip() else "No TCP ports found open")
        output.append("\nUDP Port Analysis:")
        output.append(udp_scan.stdout if udp_scan.stdout.strip() else "No UDP ports found open")
        
        return "\n".join(output)
    except Exception as e:
        return f"Port analysis failed: {str(e)}"

def perform_dns_analysis(ip):
    """Perform DNS analysis"""
    try:
        print_progress("Starting DNS analysis...")
        
        # Try multiple DNS lookup methods
        dns_info = []
        
        # Method 1: Using nslookup (fastest)
        try:
            nslookup = subprocess.run(['nslookup', ip], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            if nslookup.returncode == 0:
                dns_info.append(f"NSLookup Results:\n{nslookup.stdout}")
        except Exception as e:
            dns_info.append(f"NSLookup failed: {str(e)}")
        
        # Method 2: Using socket (fast)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            dns_info.append(f"Socket Lookup Results:\nHostname: {hostname}")
        except Exception as e:
            dns_info.append(f"Socket lookup failed: {str(e)}")
        
        # Combine results
        if not dns_info:
            return "All DNS lookup methods failed"
        
        print_progress("DNS analysis completed")
        return "\n".join(dns_info)
    except Exception as e:
        return f"DNS analysis failed: {str(e)}"

def perform_traceroute(ip):
    """Perform network topology analysis"""
    try:
        print_progress("Starting network topology analysis...")
        
        # Fast traceroute with minimal hops
        result = subprocess.run(['traceroute', '-m', '5', '-w', '1', '-q', '1', ip], 
                              capture_output=True, 
                              text=True)
        
        if result.returncode != 0:
            return "Traceroute failed to execute properly"
        
        print_progress("Network topology analysis completed")
        return result.stdout
    except Exception as e:
        return f"Network topology analysis failed: {str(e)}"

def get_osi_info():
    """Get OSI model information"""
    return """
OSI Model Information:
--------------------
Layer 7 (Application): HTTP, FTP, DNS, SMTP
Layer 6 (Presentation): SSL, TLS, JPEG, MPEG
Layer 5 (Session): NetBIOS, RPC, PPTP
Layer 4 (Transport): TCP, UDP
Layer 3 (Network): IP, ICMP, ARP
Layer 2 (Data Link): Ethernet, PPP, Frame Relay
Layer 1 (Physical): Cables, Hubs, Repeaters

Current Scan Focus:
- Layer 3: IP address validation and routing
- Layer 4: TCP/UDP port analysis
- Layer 7: DNS and service detection
"""

def analyze_report(nmap_result, port_analysis, dns_result, traceroute_result):
    """Analyze scan results and provide security insights"""
    insights = []
    
    # Analyze Nmap results
    if "Nmap scan not performed" not in nmap_result:
        open_ports = []
        services = []
        
        # Extract open ports and services
        for line in nmap_result.split('\n'):
            if '/tcp' in line and 'open' in line:
                port = line.split('/')[0]
                service = line.split()[-1]
                open_ports.append(port)
                services.append(service)
        
        # Add insights about open ports
        if open_ports:
            insights.append("\nOpen Ports Analysis:")
            insights.append(f"- Found {len(open_ports)} open ports")
            
            # Check for common vulnerable ports
            vulnerable_ports = {
                '21': 'FTP - Consider disabling if not needed',
                '22': 'SSH - Ensure strong authentication',
                '23': 'Telnet - Consider disabling (insecure)',
                '80': 'HTTP - Consider upgrading to HTTPS',
                '443': 'HTTPS - Check certificate validity',
                '445': 'SMB - Ensure proper security settings',
                '3389': 'RDP - Ensure strong authentication',
                '5900': 'VNC - Consider disabling if not needed'
            }
            
            for port in open_ports:
                if port in vulnerable_ports:
                    insights.append(f"- Port {port}: {vulnerable_ports[port]}")
    
    # Analyze DNS results
    if "DNS analysis not performed" not in dns_result:
        insights.append("\nDNS Analysis:")
        if "Could not resolve hostname" in dns_result:
            insights.append("- Hostname resolution failed - Check DNS configuration")
        else:
            insights.append("- Hostname resolution successful")
    
    # Analyze Traceroute results
    if "Network topology analysis not performed" not in traceroute_result:
        insights.append("\nNetwork Topology Analysis:")
        hops = len([line for line in traceroute_result.split('\n') if '*' not in line])
        insights.append(f"- Path to target has {hops} hops")
        if hops > 5:
            insights.append("- Warning: High number of hops may indicate network inefficiency")
    
    # Add general security recommendations
    insights.append("\nGeneral Security Recommendations:")
    insights.append("- Ensure all services are up to date")
    insights.append("- Implement proper firewall rules")
    insights.append("- Use strong authentication methods")
    insights.append("- Regularly monitor network traffic")
    insights.append("- Consider implementing IDS/IPS")
    
    return "\n".join(insights)

def generate_report(ip, nmap_result, port_analysis, dns_result, traceroute_result, selected_scans):
    """Generate comprehensive network reconnaissance report"""
    report = f"""
Network Reconnaissance Report
===========================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target IP: {ip}

Basic Information:
----------------
Hostname: {socket.getfqdn(ip)}
Is Private IP: {ipaddress.ip_address(ip).is_private}
"""
    
    if 1 in selected_scans or 5 in selected_scans:
        report += f"""
Nmap Scan Results:
----------------
{nmap_result}
"""
    
    if 2 in selected_scans or 5 in selected_scans:
        report += f"""
Port Analysis:
------------
{port_analysis}
"""
    
    if 3 in selected_scans or 5 in selected_scans:
        report += f"""
DNS Analysis:
-----------
{dns_result}
"""
    
    if 4 in selected_scans or 5 in selected_scans:
        report += f"""
Network Topology:
---------------
{traceroute_result}
"""
    
    # Add security analysis
    report += f"""
Security Analysis:
----------------
{analyze_report(nmap_result, port_analysis, dns_result, traceroute_result)}
"""
    
    return report

def run_all_scans(ip):
    """Run all scans in parallel"""
    try:
        print_progress("Starting comprehensive network analysis...")
        
        # Check if nmap is installed and offer to install if not
        if not check_and_install_nmap():
            return {"error": "Nmap is required for scanning. Please install it and try again."}
        
        def run_scan(scan_type):
            if scan_type == 'nmap':
                return perform_quick_nmap_scan(ip)
            elif scan_type == 'ports':
                return analyze_ports(ip)
            elif scan_type == 'dns':
                return perform_dns_analysis(ip)
            elif scan_type == 'traceroute':
                return perform_traceroute(ip)
        
        # Run all scans in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_scan = {
                executor.submit(run_scan, 'nmap'): 'nmap',
                executor.submit(run_scan, 'ports'): 'ports',
                executor.submit(run_scan, 'dns'): 'dns',
                executor.submit(run_scan, 'traceroute'): 'traceroute'
            }
            
            results = {}
            for future in concurrent.futures.as_completed(future_to_scan):
                scan_type = future_to_scan[future]
                try:
                    results[scan_type] = future.result()
                except Exception as e:
                    results[scan_type] = f"Error in {scan_type} scan: {str(e)}"
        
        return results
    except Exception as e:
        return {"error": f"Failed to run all scans: {str(e)}"}

def main():
    print_header()
    
    # Get IP address from user
    ip = input("\nEnter IP address to scan: ")
    
    # Validate IP
    is_valid, errors = validate_ip(ip)
    if not is_valid:
        print("\nIP Validation Errors:")
        for error in errors:
            print(f"- {error}")
        return
    
    while True:
        print_header()
        choice = show_menu()
        
        if choice == 0:
            print("\nThank you for using the Network Reconnaissance Tool!")
            break
        
        print("\nStarting network reconnaissance...")
        start_time = time.time()
        
        # Initialize results with default values
        nmap_result = "Nmap scan not performed"
        port_analysis = "Port analysis not performed"
        dns_result = "DNS analysis not performed"
        traceroute_result = "Network topology analysis not performed"
        
        selected_scans = []
        
        if choice == 1:
            selected_scans = [1]
            nmap_result = perform_quick_nmap_scan(ip)
        elif choice == 2:
            selected_scans = [2]
            port_analysis = analyze_ports(ip)
        elif choice == 3:
            selected_scans = [3]
            dns_result = perform_dns_analysis(ip)
        elif choice == 4:
            selected_scans = [4]
            traceroute_result = perform_traceroute(ip)
        elif choice == 5:
            selected_scans = [5]
            # Run all scans in parallel
            results = run_all_scans(ip)
            if isinstance(results, dict) and 'error' not in results:
                nmap_result = results.get('nmap', "Nmap scan not performed")
                port_analysis = results.get('ports', "Port analysis not performed")
                dns_result = results.get('dns', "DNS analysis not performed")
                traceroute_result = results.get('traceroute', "Network topology analysis not performed")
            else:
                print_progress("Error running all scans")
                continue
        
        # Generate and display report
        report = generate_report(ip, nmap_result, port_analysis, dns_result, traceroute_result, selected_scans)
        print(report)
        
        # Print execution time
        end_time = time.time()
        execution_time = end_time - start_time
        print_progress(f"Total execution time: {execution_time:.2f} seconds")
        
        # Ask user if they want to save the results
        save_choice = input("\nDo you want to save the scan results to a file? (y/n): ").lower()
        if save_choice == 'y':
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"network_scan_{ip}_{timestamp}.txt"
            
            try:
                with open(filename, 'w') as file:
                    file.write(report)
                print_progress(f"Scan results saved to {filename}")
            except Exception as e:
                print_progress(f"Error saving file: {str(e)}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
