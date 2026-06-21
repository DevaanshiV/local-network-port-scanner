#!/usr/bin/env python3
"""
Local Network Port Scanner
==========================
A multi-threaded TCP port scanner for educational and cybersecurity portfolio purposes.
Developed for IIT Kanpur B.Cyber degree application.

This script scans a target IP address for open ports within a specified range,
using Python's built-in libraries only (socket, threading, sys).

Author: Candidate
Date: June 2026
"""

import socket
import threading
import sys
from datetime import datetime
from typing import List, Tuple, Optional

# --- Global Configuration ---
# Maximum number of threads to run concurrently for scanning
MAX_THREADS = 200

# Timeout in seconds for each socket connection attempt
# Lower timeout = faster scanning but may miss slower services
SOCKET_TIMEOUT = 0.5

# Common service names for well-known ports (for output enhancement)
COMMON_SERVICES = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCBIND', 135: 'MSRPC',
    139: 'NETBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
    3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL',
    5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
}


class PortScanner:
    """
    Main port scanner class that handles the scanning logic, threading,
    and result collection.
    """
    
    def __init__(self, target_ip: str):
        """
        Initialize the scanner with target IP address.
        
        Args:
            target_ip: The IP address to scan (string format)
        """
        self.target_ip = target_ip
        self.open_ports: List[Tuple[int, str]] = []  # List of (port, service) tuples
        self.lock = threading.Lock()  # Lock for thread-safe access to shared data
        self.scan_completed = False    # Flag to indicate if scanning is done
        
    def scan_port(self, port: int) -> Optional[str]:
        """
        Attempt a TCP connection to a specific port on the target IP.
        
        Args:
            port: The port number to scan
            
        Returns:
            Service name if port is open, None otherwise
        """
        try:
            # Create a new socket object with IPv4 and TCP protocol
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set a timeout so we don't hang indefinitely on closed ports
            sock.settimeout(SOCKET_TIMEOUT)
            
            # Attempt to connect to the target IP and port
            # connect_ex returns 0 on success, error code otherwise (non-blocking)
            result = sock.connect_ex((self.target_ip, port))
            
            # Close the socket immediately after the attempt
            sock.close()
            
            # If result is 0, the connection succeeded -> port is open
            if result == 0:
                # Look up the service name from our dictionary, or return 'Unknown'
                service = COMMON_SERVICES.get(port, 'Unknown')
                return service
                
        except socket.gaierror:
            # This handles invalid hostnames/IP addresses at the socket level
            print(f"[ERROR] Invalid IP address or hostname: {self.target_ip}")
            sys.exit(1)
        except socket.error as e:
            # Catch other socket errors (e.g., network unreachable)
            # We don't exit here; we just treat it as a closed port
            pass
        except Exception as e:
            # Catch any unexpected errors but don't crash the scanner
            print(f"[WARNING] Unexpected error scanning port {port}: {e}")
            
        return None  # Port is closed or error occurred
    
    def worker(self, port: int) -> None:
        """
        Worker function to be executed by each thread.
        Scans a single port and adds it to the results if open.
        
        Args:
            port: The port number to scan
        """
        service = self.scan_port(port)
        
        if service:  # If port is open
            # Use a lock to prevent race conditions when appending to the list
            with self.lock:
                self.open_ports.append((port, service))
    
    def scan_range(self, start_port: int, end_port: int) -> None:
        """
        Scan a range of ports using multi-threading.
        
        Args:
            start_port: Starting port number (inclusive)
            end_port: Ending port number (inclusive)
        """
        print(f"[*] Starting scan of {self.target_ip} from port {start_port} to {end_port}")
        print(f"[*] Using up to {MAX_THREADS} concurrent threads with {SOCKET_TIMEOUT}s timeout")
        start_time = datetime.now()
        
        # Create and start threads for each port in the range
        threads = []
        active_threads = 0
        
        for port in range(start_port, end_port + 1):
            # Create a new thread for this port
            thread = threading.Thread(target=self.worker, args=(port,))
            thread.start()
            threads.append(thread)
            active_threads += 1
            
            # If we've reached the maximum thread limit, wait for some to finish
            if active_threads >= MAX_THREADS:
                # Wait for at least one thread to complete before continuing
                # This prevents overwhelming the system with too many threads
                for t in threads:
                    if t.is_alive():
                        t.join(timeout=0.1)
                # Clean up completed threads from the list
                threads = [t for t in threads if t.is_alive()]
                active_threads = len(threads)
        
        # Wait for all remaining threads to complete
        for thread in threads:
            thread.join()
        
        # Mark scan as completed
        self.scan_completed = True
        
        # Calculate and display scan duration
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"[*] Scan completed in {duration.total_seconds():.2f} seconds")
    
    def display_results(self) -> None:
        """
        Display the scanning results in a formatted ASCII table.
        """
        print("\n" + "=" * 60)
        print(f" SCAN RESULTS FOR {self.target_ip}".center(60))
        print("=" * 60)
        
        if not self.open_ports:
            print(" No open ports found in the specified range.".center(60))
            print("=" * 60)
            return
        
        # Sort ports numerically for better readability
        self.open_ports.sort(key=lambda x: x[0])
        
        # Print table header
        print("\n+-------+------------------+----------------------------------------+")
        print("| PORT  | SERVICE          | STATUS                                 |")
        print("+-------+------------------+----------------------------------------+")
        
        # Print each open port with its service
        for port, service in self.open_ports:
            print(f"| {port:<5} | {service:<16} | {'OPEN' + ' ' * 38} |")
        
        # Print table footer
        print("+-------+------------------+----------------------------------------+")
        
        # Summary statistics
        total_ports = len(self.open_ports)
        print(f"\n[✓] Found {total_ports} open port(s) out of {self.scanned_range} scanned")
        print("=" * 60)


def validate_ip(ip: str) -> bool:
    """
    Validate that the input string is a valid IPv4 address.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IPv4, False otherwise
    """
    try:
        # Try to convert the string to a socket address
        socket.inet_aton(ip)
        return True
    except socket.error:
        # Also check for localhost and common hostnames as a fallback
        if ip.lower() in ['localhost', '127.0.0.1']:
            return True
        return False


def get_user_input() -> Tuple[str, int, int]:
    """
    Prompt the user for target IP and port range.
    Includes input validation and error handling.
    
    Returns:
        Tuple of (target_ip, start_port, end_port)
    """
    print("\n" + "=" * 60)
    print("  LOCAL NETWORK PORT SCANNER - IIT Kanpur B.Cyber".center(60))
    print("=" * 60)
    
    # Get target IP with validation
    while True:
        try:
            target_ip = input("\n[?] Enter target IP address (e.g., 192.168.1.1): ").strip()
            if not target_ip:
                print("[!] IP address cannot be empty. Please try again.")
                continue
            if validate_ip(target_ip):
                break
            else:
                print("[!] Invalid IP address format. Please enter a valid IPv4 address.")
        except KeyboardInterrupt:
            print("\n[!] Input interrupted by user. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error reading input: {e}")
    
    # Get starting port with validation
    while True:
        try:
            start_port_str = input("[?] Enter starting port (e.g., 1): ").strip()
            if not start_port_str:
                print("[!] Port cannot be empty. Please try again.")
                continue
            start_port = int(start_port_str)
            if 1 <= start_port <= 65535:
                break
            else:
                print("[!] Port must be between 1 and 65535.")
        except ValueError:
            print("[!] Invalid port number. Please enter a valid integer.")
        except KeyboardInterrupt:
            print("\n[!] Input interrupted by user. Exiting...")
            sys.exit(0)
    
    # Get ending port with validation
    while True:
        try:
            end_port_str = input("[?] Enter ending port (e.g., 1024): ").strip()
            if not end_port_str:
                print("[!] Port cannot be empty. Please try again.")
                continue
            end_port = int(end_port_str)
            if start_port <= end_port <= 65535:
                break
            else:
                print(f"[!] Ending port must be between {start_port} and 65535.")
        except ValueError:
            print("[!] Invalid port number. Please enter a valid integer.")
        except KeyboardInterrupt:
            print("\n[!] Input interrupted by user. Exiting...")
            sys.exit(0)
    
    return target_ip, start_port, end_port


def main() -> None:
    """
    Main entry point of the script.
    Handles overall program flow and graceful error handling.
    """
    try:
        # Get user input with validation
        target_ip, start_port, end_port = get_user_input()
        
        # Create scanner instance
        scanner = PortScanner(target_ip)
        
        # Store the total range for summary display
        scanner.scanned_range = end_port - start_port + 1
        
        # Start the scanning process
        scanner.scan_range(start_port, end_port)
        
        # Display results
        scanner.display_results()
        
        print("\n[✓] Scan completed successfully!")
        print("[*] Press Enter to exit...")
        input()  # Wait for user input before closing
        
    except KeyboardInterrupt:
        # Graceful handling of Ctrl+C during main execution
        print("\n\n[!] Scan interrupted by user. Cleaning up...")
        print("[*] Exiting gracefully. Goodbye!")
        sys.exit(0)
    except Exception as e:
        # Catch any unexpected errors in the main flow
        print(f"\n[!] An unexpected error occurred: {e}")
        print("[*] Please check your network connection and try again.")
        sys.exit(1)


# Standard Python idiom to ensure the script runs only when executed directly
if __name__ == "__main__":
    main()
