#!/usr/bin/env python3
# ----------------------------------------------------------------------#
# FILE PROPERTIES AND AUTHOR INFO                                       #
#   fileName            basic_port_scanner                              #
#   fileType            Python 3 Script (.py)                           #
#   language            Python (v3.12)                                  #
#   author              Jeret E. Obermeyer                              #
#   courseNum           IS-4543-002                                     #
#                                                                       #
# COURSE PROJECT: PRELIM INFORMATION                                    #
#   projName            Automated Port Scanner with Service Detection   #
#   projDesc            Port-scanning tool that analyzes a target ma-   #
#                       -chine for open TCP ports and attempts to id-   #
#                       -entify services running associated with them   #
#   msNum               Milestone 05                                    #
#   msWorkStart         11/26/2024                                      #
#   msWorkEnd           11/16/2024                                      #
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
import platform                     # LIBRARY 14:  Access to underlying platform’s identifying data                     https://docs.python.org/3/library/platform.html
import os                           # LIBRARY 15:  Miscellaneous operating system interfaces                            https://docs.python.org/3/library/os.html

# PLUGINS
from service_plugins import service_plugins, register_plugin
colorama.init()

# CONSTANT VARIABLES
args = None
port_service_mapping = {}
semaphore = asyncio.Semaphore(500)
network_semaphore = asyncio.Semaphore(100)
output_file = "/home/kali/Desktop/Programs/scan_results.csv"

def parse_arguments():
    parser = argparse.ArgumentParser(description="Asynchronous Multi-Target Port Scanner")
    parser.add_argument("target", help="Target IP address, hostname, or CIDR range to scan")
    parser.add_argument("--start_port", type=int, default=1, help="Start of port range to scan")
    parser.add_argument("--end_port", type=int, default=1024, help="End of port range to scan")
    parser.add_argument("--csv_path", default="/home/kali/Desktop/service-names-port-numbers.csv", help="Path to the service names CSV file")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout for each port")
    parser.add_argument("--batch_size", type=int, default=100, help="Number of concurrent connections")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging")
    return parser

# DECLARED VARIABLES
#   VAR 01:         load_port_service_mapping
#   DESCRIPTION:    Parses and filters data from specified .csv file
def load_port_service_mapping(csv_file_path):
    port_service_mapping = {}
    try:
        with open(csv_file_path, 'r', newline='', encoding='UTF-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                service_name = row.get('Service Name') or row.get('SERVICE NAME')
                port_number = row.get('Port Number') or row.get('PORT NUMBER')
                transport_protocol = row.get('Transport Protocol') or row.get('TRANSPORT PROTOCOL')
                if service_name and port_number and 'tcp' in (transport_protocol or "").lower():
                    try:
                        if '-' in port_number:
                            start_port_range, end_port_range = map(int, port_number.split('-'))
                            for port in range(start_port_range, end_port_range + 1):
                                port_service_mapping[port] = service_name.strip()
                        else:
                            port_service_mapping[int(port_number)] = service_name.strip()
                    except ValueError:
                        pass
    except FileNotFoundError:
        print(f"CSV file not found at path: {csv_file_path}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
    return port_service_mapping

#   VAR 02:         get_service_name
#   DESCRIPTION:    Obtains service information of scanned port number
def get_service_name(port):
    return port_service_mapping.get(port, 'Unknown Service')

#   VAR 03:         clean_banner
#   DESCRIPTION:    Cleans the banner to remove excess metadata
def clean_banner(banner):
    banner = re.sub(r'<\?xml.*?\?>', '', banner, flags=re.DOTALL)
    banner = re.sub(r'<!DOCTYPE.*?>', '', banner, flags=re.DOTALL)
    banner = re.sub(r'<.*?>', '', banner, flags=re.DOTALL)
    return banner.strip()

#   VAR 04:         scan_port
#   DESCRIPTION:    Establishing socket-to-port connections
async def scan_port(target, port, timeout):
    global args
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout)
        except (ConnectionRefusedError, ConnectionResetError, asyncio.TimeoutError) as e:
            if args and args.verbose:
                print(f"Port {port}: Connection error: {type(e).__name__}: {e}")
            return None
        except asyncio.CancelledError:
            return None
        except Exception as e:
            if args and args.verbose:
                print(f"Port {port}: Unexpected error during connection: {type(e).__name__}: {e}")
                traceback.print_exc()
            return None

        try:
            if asyncio.current_task().cancelled():
                return None

            plugin_func = service_plugins.get(port)
            if plugin_func:
                banner = await asyncio.wait_for(plugin_func(reader, writer), timeout=1)
            else:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=1)
                banner = data.decode('utf-8', errors='ignore').strip()
                banner = clean_banner(banner) if banner else 'No banner'
        except (ConnectionResetError, asyncio.TimeoutError, OSError, asyncio.CancelledError) as e:
            banner = 'No banner'
            if args and args.verbose:
                print(f"Port {port}: Error reading banner: {type(e).__name__}: {e}")
        except Exception as e:
            banner = 'No banner'
            if args and args.verbose:
                print(f"Port {port}: Unexpected error during banner reading: {type(e).__name__}: {e}")
                traceback.print_exc()
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except RuntimeError:
                    pass

        service_name = get_service_name(port)
        if len(banner) > 80:
            banner = banner[:80] + '...'

        return {
            'Port': port,
            'Service': service_name,
            'Status': 'Open',
            'Banner': banner
        }

#   VAR 05:         port_scan
#   DESCRIPTION:    Port range loopback for port connectivity
async def port_scan(target, start_port, end_port, timeout, batch_size=1000):
    try: 
        start_time = time.time()
        print(f"Scanning {target} from port {start_port} to {end_port}")

        results = []
        errors = []

        def batch_ports(iterable, size):
            iterator = iter(iterable)
            while True:
                batch = list(islice(iterator, size))
                if not batch:
                    break
                yield batch

        for port_batch in batch_ports(range(start_port, end_port + 1), batch_size):
            if asyncio.current_task().cancelled():
                print("Scan cancelled.")
                break
            tasks = [scan_port(target, port, timeout) for port in port_batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    if args and args.verbose:
                        print(f"Exception occurred: {type(result).__name__}: {result}")
                    errors.append({'Error': str(result)})
                elif result:
                    results.append(result)

        elapsed_time = time.time() - start_time

        if results:
            results_table = [[f"{Fore.GREEN}{r['Port']}{Style.RESET_ALL}",
                            f"{Fore.CYAN}{r['Service']}{Style.RESET_ALL}",
                            f"{Fore.GREEN}{r['Status']}{Style.RESET_ALL}",
                            r['Banner']] for r in results]
            print(tabulate(results_table, headers=['Port', 'Service', 'Status', 'Banner']))
            log_scan_results_to_file(results, "/home/kali/Desktop/Programs/scan_results.csv")
        else:
            print("No open ports found.")

        if errors and args.verbose:
            print("\nErrors encountered during scanning:")
            error_table = [[e.get('Port', 'Unknown'), e['Error']] for e in errors]
            print(tabulate(error_table, headers=['Port', 'Error Message']))

        print(f"\nScanning of {target} completed in {elapsed_time:.2f} seconds.")
    except Exception as e:
        print(f"An error occurred during port scan of {target}: {e}")
        traceback.print_exc()

#   VAR 06:         is_host_alive
#   DESCRIPTION:    Network address loopback
async def is_host_alive(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = f"ping {param} 1 {ip}"
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await proc.communicate()
    return proc.returncode == 0

#   VAR 07:         scan_network
#   DESCRIPTION:    Network subnet range loopback
async def scan_network(target_range, start_port, end_port, timeout):
    try:
        print(f"Starting network scan for {target_range}")
        network = ipaddress.ip_network(target_range, strict=False)
        tasks = []
        for ip in network.hosts():
            if asyncio.current_task().cancelled():
                print("Scan cancelled.")
                break
            if not await is_host_alive(str(ip)):
                print(f"Host {ip} is not alive. Skipping.")
                continue
            task = asyncio.create_task(
                scan_single_host(str(ip), start_port, end_port, timeout)
            )
            tasks.append(task)
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    print(f"Error scanning IP: {result}")
    except ValueError as e:
        print(f"Invalid network: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during network scan: {e}")
        traceback.print_exc()

#   VAR 08:         scan_single_host
#   DESCRIPTION:    Asynchronous semaphore for single-address scans
async def scan_single_host(ip, start_port, end_port, timeout):
    async with network_semaphore:
        await port_scan(ip, start_port, end_port, timeout)

#   VAR 09:         log_scan_results_to_file
#   DESCRIPTION:    Redirects scan output to file in directory
def log_scan_results_to_file(results, output_file):
    try:
        directory = os.path.dirname(output_file)
        if not directory or not os.path.isdir(directory):
            raise FileNotFoundError(f"Directory does not exist: {directory}")
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write("Port,Service,Status,Banner\n")
            for result in results:
                port = result.get('Port', 'Unknown')
                service = result.get('Service', 'Unknown Service')
                status = result.get('Status', 'Unknown')
                banner = result.get('Banner', '').replace('\n', ' ').replace(',', ';')
                file.write(f"{port},{service},{status},{banner}\n")
        print(f"\nScan results successfully logged to {output_file}")
    except FileNotFoundError as e:
        print(f"\nFailed to log scan results: {e}")
    except Exception as e:
        print(f"\nUnexpected error while logging scan results: {e}")

# FUNCTIONS
#   FUNC 01:        Scanner Function
#   DESCRIPTION:    Handles IP or hostname resolution for GUI interface
async def main_async(parsed_args):
    global args
    args = parsed_args
    global port_service_mapping
    port_service_mapping = load_port_service_mapping(args.csv_path)

    try:
        if '/' in args.target:
            await scan_network(args.target, args.start_port, args.end_port, args.timeout)
        else:
            try:
                target_ip = socket.gethostbyname(args.target)
                await port_scan(target_ip, args.start_port, args.end_port, args.timeout)
            except socket.gaierror:
                print(f"Could not resolve hostname: {args.target}")
            except Exception as e:
                print(f"Unexpected error: {e}")
    except asyncio.CancelledError:
        print("Scan cancelled by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()

#   FUNC 02:        Function Argument Parser
#   DESCRIPTION:    Handles arguments for GUI interface
def main(parsed_args):
    asyncio.run(main_async(parsed_args))

#   FUNC 03:        Scanner Function
#   DESCRIPTION:    Processes IP or hostname resolution
if __name__ == "__main__":
    parser = parse_arguments()
    args = parser.parse_args()
    main(args)
