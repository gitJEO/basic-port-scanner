# ----------------------------------------------------------------------#
# FILE PROPERTIES AND AUTHOR INFO                                       #
#   fileName            basic_port_scanner                              #
#   fileType            Plain Text Document (.txt)                      #
#   language            Python 3 (11.9)                                 #
#   author              Jeret E. Obermeyer                              #
#   courseNum           IS-4543-002                                     #
#                                                                       #
# COURSE PROJECT: PRELIM INFORMATION                                    #
#   projName            Automated Port Scanner with Service Detection   #
#   projDesc            Port-scanning tool that analyzes a target ma-   #
#                       -chine for open TCP ports and attempts to id-   #
#                       -entify services running associated with them   #
#   ms#                 Milestone 02                                    #
#   msWorkStart         10/19/2024                                      #
#   msWorkEnd           10/24/2024                                      #
#                                                                       #
#                 Copyright (c) 2024, UT at San Antonio                 #
# ----------------------------------------------------------------------#

# Python Standard Library
# MODULES                           LIBRARY TYPE                                                                      SOURCE CODE
import socket                       # LIBRARY 01:  low-level networking interface                                      https://github.com/python/cpython/tree/3.13/Lib/socket.py
import argparse                     # LIBRARY 02:  Parser for command-line options, arguments and subcommands          https://docs.python.org/3/library/argparse.html
import threading                    # LIBRARY 03:  Thread-based parallelism                                            https://github.com/python/cpython/tree/3.13/Lib/threading.py
import time                         # LIBRARY 04:  Time access and conversions                                         https://docs.python.org/3/library/time.html#module-time
import csv                          # LIBRARY 05:  File reading and writing                                            https://github.com/python/cpython/blob/3.13/Lib/csv.py
import concurrent.futures           # LIBRARY 06:  High-level interface for asynchronously executing callables         https://docs.python.org/3/library/concurrent.futures.html#module-concurrent.futures
import sys                          # LIBRARY 07:  System-specific parameters and functions                            https://docs.python.org/3/library/sys.html#module-sys
from tabulate import tabulate       # LIBRARY 08:  Displays results in a table with columns for specified fields       https://github.com/astanin/python-tabulate 
from colorama import Fore, Style    # LIBRARY 09:  Use colors to highlight open ports or errors                        https://github.com/tartley/colorama
import colorama                     # LIBRARY 10:  Import colorama                                                     https://github.com/tartley/colorama
import re                           # LIBRARY 11:  For regular expressions to clean banner                             https://github.com/python/cpython/tree/3.13/Lib/re/

# CONSTANTS
parser = argparse.ArgumentParser(description = "Basic Port Scanner")                                                                                # The description of the custom argument/command line
parser.add_argument("target", help = "Target IP address or hostname to scan")                                                                       # param1   Sets the target IP address to scan and explains functionality when help() is called
parser.add_argument("--start_port", type = int, default = 1, help = "Start of port range to scan")                                                  # param2   Sets the starting port range to scan based on IP address in param1 
parser.add_argument("--end_port", type = int, default = 1024, help = "End of port range to scan")                                                   # param2   Sets the ending port range to scan based on IP address in param1 
parser.add_argument("--csv_path", default = "/home/kali/Desktop/service-names-port-numbers.csv", help = "Path to the service names CSV file")       # param3   Sets the preferred directory for scanning criteria
args = parser.parse_args()                                                                                                                          # Runs the parser and places the extracted data in a argparse.Namespace object (see: ArgumentParser.parse_args())
target = args.target                                                                                                                                # Initializes "target" as a constant object
start_port = args.start_port                                                                                                                        # Initializes "start_port" ... 
end_port = args.end_port                                                                                                                            # Initializes "end_port" ... 
lock = threading.Lock()                                                                                                                             # Initializes lock instance from threading module/library
colorama.init()                                                                                                                                     # Initialized colorama for tabular output formatting

# VARIABLES
#   VAR 01:         load_port_service_mapping
#   DESCRIPTION:    Parses and filters data from specified .csv file
def load_port_service_mapping(csv_file_path):
    # Initialize empty dictionary for mappings
    port_service_mapping = {}
    # Open CSV file for reading
    with open(csv_file_path, 'r', newline='', encoding='UTF-8') as csvfile:
        # Create a CSV dictionary reader
        reader = csv.DictReader(csvfile)
        # Iterate over each row in CSV
        for row in reader:
            # Get 'Service Name' from row
            service_name = row.get('Service Name') or row.get('SERVICE NAME')
            # Get 'Port Number' from row
            port_number = row.get('Port Number') or row.get('PORT NUMBER')
            # Get 'Transport Protocol' from row
            transport_protocol = row.get('Transport Protocol') or row.get('TRANSPORT PROTOCOL')
            # Checks whether all variables exist
            if service_name and port_number and transport_protocol:
                # Checks if transport_protocol() variable contains tcp
                if 'tcp' in transport_protocol.lower():
                    # Try-catch Expression: Returns "if '-' [...]" if true
                    try:
                        # Checks if port number is a range
                        if '-' in port_number:
                            # Splits range and generates output as integers
                            start_port_range, end_port_range = map(int, port_number.split('-'))
                            # Iterate over port range
                            for port in range(start_port_range, end_port_range + 1):
                                # Map port to service name
                                port_service_mapping[port] = service_name.strip()
                        # Checks if port number is not a range
                        else:
                            # Converts port number to integer
                            port = int(port_number.strip())
                            # Correlates port number to service name
                            port_service_mapping[port] = service_name.strip()
                    # Catches inputs with invalid number format and silently ignores
                    except ValueError:
                        pass
    return port_service_mapping

# Stores port number and service information from .CSV to port_service_mapping
port_service_mapping = load_port_service_mapping(args.csv_path)

#   VAR 02:         get_service_name
#   DESCRIPTION:    Obtains service information of scanned port number
def get_service_name(port):
    return port_service_mapping.get(port, 'Unknown Service')

#   VAR 03:         clean_banner
#   DESCRIPTION:    Cleans the banner to remove excess metadata
def clean_banner(banner):
    # Removes XML declaration
    banner = re.sub(r'<\?xml.*?\?>', '', banner, flags=re.DOTALL)
    # Removes DOCTYPE declaration
    banner = re.sub(r'<!DOCTYPE.*?>', '', banner, flags=re.DOTALL)
    # Removes HTML tags
    banner = re.sub(r'<.*?>', '', banner, flags=re.DOTALL)
    return banner.strip()

#   VAR 04:         scan_port
#   DESCRIPTION:    Establishing socket-to-port connections
def scan_port(target, port):
    try:
        # Creates a TCP socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Sets socket timeout to half of a second
            s.settimeout(0.5)
            # Attempts to connect to the target port
            result = s.connect_ex((target, port))
            # Checks if the connection was successful
            if result == 0:
                # Initializes banner as an empty string
                banner = ''
                # Sets a timeout for recv before receiving data
                s.settimeout(0.5)
                try:
                    # Receives initial data (banner) from the socket
                    banner = s.recv(4096).decode('UTF-8', errors='ignore').strip()
                except Exception:
                    pass

                if not banner:
                    # Checks if port is an HTTP port
                    if port in [80, 8080, 8443]:
                        # Prepares an HTTP GET request
                        http_request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                        # Sends the HTTP GET request
                        s.sendall(http_request.encode())
                        s.settimeout(0.5)
                        try:
                            # Receives the response after the request
                            banner = s.recv(4096).decode('UTF-8', errors='ignore').strip()
                        except Exception:
                            pass
                    # Checks if port is a common service port
                    elif port in [21, 22, 25, 110, 143]:
                        pass
                    else:
                        # Transmits a generic request to elicit a response
                        s.sendall(b"\r\n")
                        s.settimeout(0.5)
                        try:
                            # Receives the response from the port
                            banner = s.recv(1024).decode('UTF-8', errors='ignore').strip()
                        except Exception:
                            pass

                # Retrieves the service name for the port
                service_name = get_service_name(port)

                # Cleans banner to remove excess metadata
                if banner:
                    banner = clean_banner(banner)

                # Handles long banners post-clean
                max_banner_length = 80
                if banner and len(banner) > max_banner_length:
                    banner = banner[:max_banner_length] + '...'

                # Initializes the result as a dictionary
                result_data = {
                    'Port': port,
                    'Service': service_name,
                    'Status': 'Open',
                    'Banner': banner or 'No banner'
                }

                return result_data

    except socket.timeout:
        # Timeout Exception handle
        return None
    except socket.error as e:
        # Socket Error Exception handle
        return None
    except ValueError as e:
        # Log Value Error Exception handle
        return None

    return None

#   VAR 05:         port_scan
#   DESCRIPTION:    Port range loopback for port connectivity
def port_scan(target, start_port, end_port):
    try:
        # Checks whether inputted port values are valid (1-65535) and if start_port is less than or equal to end_port
        if (1 <= start_port <= 65535) and (1 <= end_port <= 65535) and (start_port <= end_port):
            # Runtime stopwatch: records time between scans
            start_time = time.time()
            # Prints stored target(), start_port(), and end_port() as f-string values
            print(f"Scanning target {target} from port {start_port} to {end_port}")
            # Compiled threaded list of open port results
            results = []

            # Processes and stores scanned ports using threads
            def threaded_scan(port):
                # Stores the scanned ports as result
                result = scan_port(target, port)
                if result:
                    # Ensures control over frequency of writes to results[] and appends them accordingly
                    with lock:
                        results.append(result)

            # Sets a numeric limitation on the number of threads to prevent overexhaustion; adjust discretionarily
            max_workers = 500
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Schedules threaded_scan to be executed immediately after scanning a port
                future_to_port = {executor.submit(threaded_scan, port): port for port in range(start_port, end_port + 1)}
                for future in concurrent.futures.as_completed(future_to_port):
                    # Maps "futures" (scanned ports) to their corresponding port numbers
                    port = future_to_port[future]
                    try:
                        future.result()
                    except Exception as exc:
                        print(f'Port {port} generated an exception: {exc}')

            # Runtime stopwatch: finishes recording time after final port scan
            end_time = time.time()
            elapsed_time = end_time - start_time

            if results:
                # Initiates scan data tabulation
                results_table = []
                for result in results:
                    port_num    =   result['Port']
                    service     =   result['Service']
                    status      =   result['Status']
                    banner      =   result['Banner']
                    # Invokes color coding using colorama import
                    port_str    =   f"{Fore.GREEN}{port_num}{Style.RESET_ALL}"
                    service_str =   f"{Fore.CYAN}{service}{Style.RESET_ALL}"
                    status_str  =   f"{Fore.GREEN}{status}{Style.RESET_ALL}"
                    results_table.append([port_str, service_str, status_str, banner])

                # Displays the results in a table
                print(tabulate(results_table, headers=['Port', 'Service', 'Status', 'Banner']))
            else:
                print("No open ports found in the specified range.")

            # Writes to log file to store results
            with open("scan_results.txt", "w") as log_file:
                # Writes the raw results
                for result in results:
                    log_file.write(f"Port {result['Port']} ({result['Service']}) is {result['Status']}: {result['Banner']}\n")
                log_file.write(f"Scanning completed in {elapsed_time:.2f} seconds.\n")

            with open('scan_results.csv', 'w', newline = '', encoding = 'utf-8') as csvfile:
                csv_writer = csv.writer(csvfile)
                # Writes the header
                csv_writer.writerow(['Port', 'Service', 'Status', 'Banner'])
                # Writes the data rows
                for result in results:
                    csv_writer.writerow([result['Port'], result['Service'], result['Status'], result['Banner']])

            # Prints recalculated elapsed_time value to output
            print(f"Scanning completed in {elapsed_time:.2f} seconds.")

        else:
            # Prints termination of scan due to invalid port range before terminating the sequence
            print("Scan terminated: invalid port range (must be 1 <= --start_port <= --end_port <= 65535)")
            sys.exit()
    # Processes exceptions as they occur
    except socket.timeout:
        print(f"Timeout occurred while scanning port {port}")
        sys.exit(1)
    except socket.error as e:
        print(f"Socket error on port {port}: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"ValueError: {e}")
        sys.exit(1)

# FUNCTIONS

#   FUNC 01:        Scanner Function
#   DESCRIPTION:    Handles IP or hostname resolution

# Checks whether the scanner is being run directly
if __name__ == "__main__":
    try:
        # Attempts to resolve scan target and convert hostname to its corresponding IP address
        target_ip = socket.gethostbyname(target)
        port_scan(target_ip, start_port, end_port)
    # Catches unresolvable hostnames and exits
    except socket.gaierror as e:
        print(f"Could not resolve hostname: {target}")
        sys.exit(1)
    # Global exception handler for unexpected errors/exceptions
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
