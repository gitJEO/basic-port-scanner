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
#   ms#                 Milestone 01                                    #
#   msWorkStart         10/16/2024                                      #
#   msWorkEnd           10/02/2024                                      #
#                                                                       #
#                 Copyright (c) 2024, UT at San Antonio                 #
# ----------------------------------------------------------------------#

# Python Standard Library
# MODULES                 LIBRARY TYPE                                                                    SOURCE CODE
import socket           # LIBRARY 01: low-level networking interface                                      https://github.com/python/cpython/tree/3.13/Lib/socket.py
import argparse         # LIBRARY 02: Parser for command-line options, arguments and subcommands          https://docs.python.org/3/library/argparse.html
import threading        # LIBRARY 03: Thread-based parallelism                                            https://github.com/python/cpython/tree/3.13/Lib/threading.py
import time             # LIBRARY 04: Time access and conversions                                         https://docs.python.org/3/library/time.html#module-time

# CONSTANTS
parser = argparse.ArgumentParser(description = "Basic Port Scanner")                                    # The description of the custom argument/command line
parser.add_argument("target", help = "Target IP address or hostname to scan")                           # param1   Sets the target IP address to scan and explains functionality when help() is called
parser.add_argument("--start_port", type = int, default = 1, help = "Start of port range to scan")      # param2   Sets the starting port range to scan based on IP address in param1 
parser.add_argument("--end_port", type = int, default = 1024, help = "End of port range to scan")       # param2   Sets the ending port range to scan based on IP address in param1 
args = parser.parse_args()                                                                              # Runs the parser and places the extracted data in a argparse.Namespace object (see: ArgumentParser.parse_args())
target = args.target                                                                                    # Initializes "target" as a constant object
start_port = args.start_port                                                                            # Initializes "start_port" ... 
end_port = args.end_port                                                                                # Initializes "end_port" ... 


# VARIABLES
#   VAR 01:         scan_port
#   DESCRIPTION:    Establishing socket-to-port connections
def scan_port(target, port):                                                                            # Input parameters for scan_port
    try:                                                                                                #   Beginning of try-catch for targeted ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:                                    #       Utilizes 'socket' class from socket library for IPv4/TCP endpoint communication, stored as 's'
            s.settimeout(0.5)                                                                           #           Set timeout for each connection attempt
            result = s.connect_ex((target, port))                                                       #           Attempts to connect and returns an error indicator instead of raising an exception if host is unreachable
            if result == 0:                                                                             #           Evaluates the return value of s.connext_ex()
                print(f"Port {port} is open")                                                           #               Printed output of open port 
                return f"Port {port} is open\n"                                                         #               Calls log_file() for output to be written to another path
    except Exception as e:                                                                              #       Catches unreachable port numbers
        print(f"Error scanning port {port}: {e}")                                                       #           Printed output of closed port or timeout 
    return None                                                                                         #       Return None if port is ERR or closed

#   VAR 02:         port_scan
#   DESCRIPTION:    Port range loopback for port connectivity
lock = threading.Lock()                                                                                 # Lock instance declared in-variable from threading module/library

def port_scan(target, start_port, end_port):                                                            # Formatted output from scan_port
    if (0 <= start_port <= 65535) and (start_port <= end_port <= 65535):                                #   Checks if start_port is greater than 0 but less than 65535 AND if end_port is greater than or equal to start_port and less than 65535
        start_time = time.time()                                                                        #       Runtime stopwatch: records time between scans
        print(f"Scanning target {target} from port {start_port} to {end_port}")                         #       Prints stored target(), start_port(), and end_port() as f-string values
        threads = []                                                                                    #       Default threated list of ports being scanned
        results = []                                                                                    #       Compiled threaded list of open port results 

        def threaded_scan(target, port):                                                                #       Processes and stores scanned ports using threads 
            result = scan_port(target, port)                                                            #           Stores the scanned ports as result
            if result:                                                                                  #           Checks for errors
                with lock:                                                                              #               Ensures control over frequency of writes to results[]
                    results.append(result)                                                              #                   Appends  port scans to results[]
        for port in range(start_port, end_port + 1):                                                    #       Iterates over the desired port range
            thread = threading.Thread(target=threaded_scan, args=(target, port))                        #           Creates thread to scan a port
            threads.append(thread)                                                                      #           Appends each new thread to threads[]
            thread.start()                                                                              #           Begins scanning the thread
        for thread in threads:                                                                          #       Iterates over all threads for completion
            thread.join()                                                                               #           Run the next sequence upon completion of thread 
        
        end_time = time.time()                                                                          #       Runtime stopwatch: finishes recording time after final port scan
        elapsed_time = end_time - start_time                                                            #       Calculate the elapsed time 
        with open("scan_results.txt", "w") as log_file:                                                 #       Writes to log file to store results
            for result in results:                                                                      #           Iterates over results
                log_file.write(result)                                                                  #               Writes each result to log file
            log_file.write(f"Scanning completed in {elapsed_time:.2f} seconds.\n")                      #           Prints time elapsed in seconds to output
        print(f"Scanning completed in {elapsed_time:.2f} seconds.")                                     #       Prints recalculated elapsed_time value to output
    else:                                                                                               #   If-else Expression
        print("Scan terminated: invalid port range (must be --start_port < x < 65535)")                 #       Prints termination message
        exit()                                                                                          #       Script termination

# FUNCTIONS
#   FUNC 01:        Scanner Function
#   DESCRIPTION:    HandleS IP or hostname resolution
if __name__ == "__main__":                                                                              # Checks whether the scanner is being ran directly
    try:                                                                                                #   Beginning of try-catch for nature of code execution
        target_ip = socket.gethostbyname(target)                                                        #       Attempts to resolve scan target and convert hostname to its corresponding IP address
    except socket.gaierror:                                                                             #   Catches unresolvable hostnames
        print(f"Could not resolve hostname: {target}")                                                  #       Printed output of unresolved hostnames
        exit()                                                                                          #       Script termination
    port_scan(target_ip, start_port, end_port)                                                          #   Calls port_scan() with resolved IP address and specified port range to initiate scanning
