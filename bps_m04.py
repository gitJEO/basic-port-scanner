#!/usr/bin/env python3
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
#   msNum               Milestone 03                                    #
#   msWorkStart         10/25/2024                                      #
#   msWorkEnd           11/07/2024                                      #
#                                                                       #
#                 Copyright (c) 2024, UT at San Antonio                 #
# ----------------------------------------------------------------------#

# Python Standard Library
# MODULES                           LIBRARY TYPE                                                                        SOURCE CODE
import socket                       # LIBRARY 01:  low-level networking interface                                       https://github.com/python/cpython/tree/3.13/Lib/socket.py
import argparse                     # LIBRARY 02:  Parser for command-line options, arguments and subcommands           https://docs.python.org/3/library/argparse.html
import time                         # LIBRARY 04:  Time access and conversions                                          https://docs.python.org/3/library/time.html#module-time
import csv                          # LIBRARY 05:  File reading and writing                                             https://github.com/python/cpython/blob/3.13/Lib/csv.py
import asyncio                      # LIBRARY 06:  Concurrent programming design for high-performance network queues    https://realpython.com/async-io-python/
import colorama                     # LIBRARY 07:  Import colorama                                                      https://github.com/tartley/colorama
import re                           # LIBRARY 08:  For regular expressions to clean banner                              https://github.com/python/cpython/tree/3.13/Lib/re/
import ipaddress                    # LIBRARY 09:  IPv4/IPv6 manipulation library                                       https://github.com/python/cpython/blob/3.13/Lib/ipaddress.py 
from tabulate import tabulate       # LIBRARY 10:  Displays results in a table with columns for specified fields        https://github.com/astanin/python-tabulate 
from colorama import Fore, Style    # LIBRARY 11:  Use colors to highlight open ports or errors                         https://github.com/tartley/colorama
from itertools import islice        # LIBRARY 12:  Functions creating iterators for efficient looping                   https://docs.python.org/3/library/itertools.html
import traceback                    # LIBRARY 13:  Print or retrieve a stack traceback                                  https://docs.python.org/3/library/traceback.html

# PLUGINS                                                                                                               PATH
from service_plugins import service_plugins, register_plugin                                                        #   /home/kali/Desktop/Programs/service_plugins.py

# CONSTANTS
parser = argparse.ArgumentParser(description="Asynchronous Multi-Target Port Scanner")                                                              # The description of the custom argument/command line
parser.add_argument("target", help="Target IP address, hostname, or CIDR range to scan")                                                            # param1   Sets the target IP address to scan and explains functionality when help() is called
parser.add_argument("--start_port", type = int, default = 1, help = "Start of port range to scan")                                                  # param2   Sets the starting port range to scan based on IP address in param1 
parser.add_argument("--end_port", type = int, default = 1024, help = "End of port range to scan")                                                   # param2   Sets the ending port range to scan based on IP address in param1 
parser.add_argument("--csv_path", default = "/home/kali/Desktop/service-names-port-numbers.csv", help = "Path to the service names CSV file")       # param3   Sets the preferred directory for scanning criteria
parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout for each port")                                                      # param4   Sets the timeout value for each port scan
parser.add_argument("--batch_size", type=int, default=100, help="Number of concurrent connections")                                                 # param5   Sets the batch size value for the scan
parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging")

args = parser.parse_args()                                                                                                                          # Runs the parser and places the extracted data in a argparse.Namespace object (see: ArgumentParser.parse_args())
colorama.init()                                                                                                                                     # Initialized colorama for tabular output formatting

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
            # Check whether only TCP ports are mapped with valid service names and port numbers
            if service_name and port_number and 'tcp' in (transport_protocol or "").lower():
                try:
                    # Checks if port number is a range
                    if '-' in port_number:
                        # Splits range and generates output as integers
                        start_port_range, end_port_range = map(int, port_number.split('-'))
                        # Interate over port range
                        for port in range(start_port_range, end_port_range + 1):
                            # Map port to service name
                            port_service_mapping[port] = service_name.strip()
                    # Checks if port number is not a range
                    else:
                        # Maps individual ports then assigns to service_name to be reformatted
                        port_service_mapping[int(port_number)] = service_name.strip()
                except ValueError:
                    # Ignore rows with invalid number formats
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
# Defines the adjustable maximum number of concurrent tasks
semaphore = asyncio.Semaphore(1000)

async def scan_port(target, port, timeout):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)

            # Check for a service detection plugin
            plugin_func = service_plugins.get(port)
            if plugin_func:
                # Use the plugin to detect the service
                banner = await plugin_func(reader, writer)
            else:
                # Default banner grabbing
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(4096), timeout=1)
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner:
                        banner = clean_banner(banner)
                    else:
                        banner = 'No banner'
                except Exception:
                    banner = 'No banner'

            writer.close()
            await writer.wait_closed()
            service_name = get_service_name(port)
            if len(banner) > 80:
                banner = banner[:80] + '...'
            return {
                'Port': port,
                'Service': service_name,
                'Status': 'Open',
                'Banner': banner
            }
        except Exception as e:
            if args.verbose:
                print(f"Exception when connecting to port {port}: {type(e).__name__}: {e}")
                traceback.print_exc()
            return None

#   VAR 05:         port_scan
#   DESCRIPTION:    Port range loopback for port connectivity
async def port_scan(target, start_port, end_port, timeout, batch_size=1000):
    # Begins runtime
    start_time = time.time()
    print(f"Scanning {target} from port {start_port} to {end_port}")

    # Delcares in-variable list to store successfully scanned port information and error information
    results = [] 
    errors = []

    # Divides ports into batches
    def batch_ports(iterable, size):
        iterator = iter(iterable)
        while True:
            # Creates a list for the current batch from scanned batch_size
            batch = list(islice(iterator, size))
            # Stops when no more scannable ports remain
            if not batch:
                break
            # Yields batch of ports
            yield batch

    # Batch the port ranges and scan each batch concurrently
    for port_batch in batch_ports(range(start_port, end_port + 1), batch_size):
        # Creates a list of asynchronous scan tasks for the current scanned batch
        tasks = [scan_port(target, port, timeout) for port in port_batch]
        # Waits for completion of all tasks
        batch_results = await asyncio.gather(*tasks)
        # Processes subsequent results from current scanned batch
        for result in batch_results:
            # Checks results for errors from scanned results 
            if result:
                if 'Error' in result:
                    # Appends error results to the errors list
                    errors.append(result)
                else:
                    # Appends successful results to results list
                    results.append(result)

    # Calculates the elapsed runtime
    elapsed_time = time.time() - start_time

    # Display results and errors
    if results:
        results_table = [[f"{Fore.GREEN}{r['Port']}{Style.RESET_ALL}", 
                          f"{Fore.CYAN}{r['Service']}{Style.RESET_ALL}", 
                          f"{Fore.GREEN}{r['Status']}{Style.RESET_ALL}", 
                          r['Banner']] for r in results]
        # Prints a formatted table with details about each open port
        print(tabulate(results_table, headers=['Port', 'Service', 'Status', 'Banner']))
    else:
        # Prints no open ports from scan range
        print("No open ports found.")

    # Checks for errors from error_table
    if errors:
        # Prints separately under results if any are present
        print("\nErrors encountered during scanning:")
        error_table = [[e['Port'], e['Error']] for e in errors]
        print(tabulate(error_table, headers=['Port', 'Error Message']))

    print(f"\nScanning of {target} completed in {elapsed_time:.2f} seconds.")

#   VAR 06:         scan_network
#   DESCRIPTION:    Network subnet range loopback
async def scan_network(target_range, start_port, end_port, timeout):
    try:
        # Parses target range and iterates over each host IP
        network = ipaddress.ip_network(target_range, strict=False)
        tasks = []
        # Checks for host IP in Local Area Network
        for ip in network.hosts():
            tasks.append(port_scan(str(ip), start_port, end_port, timeout))
            await asyncio.gather(*tasks)
    except ValueError as e:
        # Handle invalid network input
        print(f"Invalid network: {e}")


# FUNCTIONS

#   FUNC 01:        Scanner Function
#   DESCRIPTION:    Handles IP or hostname resolution
if __name__ == "__main__":
    if '/' in args.target:
        # Scans a network range if target is in CIDR notation
        asyncio.run(scan_network(args.target, args.start_port, args.end_port, args.timeout))
    # If network range is not in CIDR notation
    else:
        try:
            # Resolves hostname to IP
            target_ip = socket.gethostbyname(args.target)
            asyncio.run(port_scan(target_ip, args.start_port, args.end_port, args.timeout))
        except socket.gaierror:
            print(f"Could not resolve hostname: {args.target}")
        except Exception as e:
            print(f"Unexpected error: {e}")
