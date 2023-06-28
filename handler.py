import os
import os.path
import subprocess
import time
import logging
import signal
import socket
import sys
import shutil
import getopt
from ppadb.client import Client as AdbClient

# CONSTANTS
AIRPLANE_TOGGLE_NUMBER = 5
FAILED_TEST_RETRY = 3

# Set logging level
logging.basicConfig(level=logging.DEBUG)

# get arguments of the function
# test_type can be 'nas' or 'rrc'
test_type = None
try:
    opts, args = getopt.getopt(sys.argv[1:], "ht:")
except getopt.GetoptError:
    print("Usage: python3 handler.py -t <value>")
    sys.exit(1)

if len(sys.argv) != 3:
    print("Usage: python3 handler.py -t <value>")
    sys.exit(1)

for opt, arg in opts:
    if opt == "-t":
        if arg.lower() in ['nas', 'rrc']:
            test_type = arg.lower()
        else:
            print('Please enter a valid test type. Valid options are "nas" or "rrc".')
            sys.exit(1)
    else:
        print("Usage: python3 handler.py -t <value>")
        sys.exit(1)


# signal handler for ctrl-c
def exit_handler(signum, frame):
    print("Received SIGINT, shutting down.\n")
    kill_srsenb_services()
    time.sleep(3)
    kill_open5gs_services()
    time.sleep(3)
    exit(0)


signal.signal(signal.SIGINT, exit_handler)


# create folders for logs
def create_folders(name):
    folder_name = name + '_results'
    subfolder_names = ['adb', 'amf', 'enb', 'pcap']
    if name == 'rrc':
    	subfolder_names.append('gnb_pcap')
    # all permissions for everyone
    permissions = 0o777
    subfolder_dirs = []

    try:
        # Create the main folder
        os.mkdir(folder_name, permissions)
        logging.debug('Main folder created successfully.')
    except FileExistsError:
        logging.warning('Folder already exists.')
    # Create the subfolders
    for subfolder_name in subfolder_names:
        try:
            subfolder_path = os.path.join(folder_name, subfolder_name)
            subfolder_dirs.append(subfolder_path)
            os.mkdir(subfolder_path)
            os.chmod(subfolder_path, permissions)  # Set permissions for the subfolder
            print(f'Subfolder {subfolder_name} created successfully.')
        except FileExistsError:
            logging.warning('Subfolders already exist.')
    return subfolder_dirs


def log_result(filename, result):
    global result_log_path
    with open(result_log_path, 'a') as f:
        # write to log after each test
        f.write(filename + ',' + result + '\n')
        f.close()


def close_ports(hosts_and_ports):
    for [host, port] in hosts_and_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout value for the connection

        try:
            # Try to connect to the host and port
            result = sock.connect_ex((host, port))
            if result == 0:
                # Port is open, close the connection
                sock.close()
                print(f"Host {host} and port {port} closed successfully.")
            else:
                print(f"Host {host} and port {port} is already closed.")
        except socket.timeout:
            print(f"Timeout: Host {host} and port {port} is not open.")
        except Exception as e:
            print(f"An error occurred while closing host {host} and port {port}: {str(e)}")


# List of hosts and ports to close
hosts_and_ports_to_close = [
    ['127.0.0.2', 36412],  # MME-s1ap
    ['127.0.0.2', 2123],  # MME-gtpc
    ['127.0.0.2', 3868],  # MME-frDi
    ['127.0.0.3', 2123],  # SGWC-gtpc
    ['127.0.0.3', 8805],  # SGWC-pfcp
    ['127.0.0.4', 2123],  # SMF-gtpc
    ['127.0.0.4', 2152],  # SMF-gtpu
    ['127.0.0.4', 8805],  # SMF-pfcp
    ['127.0.0.4', 3868],  # SMF-frDi
    ['127.0.0.4', 7777],  # SMF-sbi
    ['127.0.0.5', 38412],  # AMF-ngap
    ['127.0.0.5', 7777],  # AMF-sbi
    ['127.0.0.6', 8805],  # SGWU-pfcp
    ['127.0.0.6', 2152],  # SGWU-gtpu
    ['127.0.0.7', 8805],  # UPF-pfcp
    ['127.0.0.7', 2152],  # UPF-gtpu
    ['127.0.0.8', 3868],  # HSS-frDi
    ['127.0.0.9', 3868],  # PCRF-frDi
    ['127.0.0.10', 7777],  # NRF-sbi
    ['127.0.1.10', 7777],  # SCP-sbi
    ['127.0.0.11', 7777],  # AUSF-sbi
    ['127.0.0.12', 7777],  # UDM-sbi
    ['127.0.0.13', 7777],  # PCF-sbi
    ['127.0.0.14', 7777],  # for 5G SBI
    ['127.0.0.15', 7777],  # for 5G SBI
    ['127.0.0.20', 7777],
]


def device_toggling():
    try:
        client = AdbClient(host="127.0.0.1", port=5037)
        # connect to all devices
        devices = client.devices()
        device = devices[0]
        device.shell("cmd connectivity airplane-mode disable")
        time.sleep(4)
        device.shell("cmd connectivity airplane-mode enable")
        time.sleep(4)
    except:
        logging.critical("ADB Error, please connect phone.")
        exit(-1)


def get_result(amf_log_file_path, filename):
    if os.path.isfile(amf_log_file_path):

        with open(amf_log_file_path, "r") as file:
            found = False
            search_text = "Testing finished!"
            for line in file:
                if search_text in line:
                    found = True
                    break

            if found:
                logging.info("---------------------------")
                logging.info(filename + " Completed!")
                log_result(filename, "completed")
                logging.info("---------------------------")
                return True

            else:
                return False

    else:
        # TODO: this part doesn't work
        logging.error('AMF log does not exist')
        all_termination(logcat, tcpdump, srsgnb, open5gs)
        #close_ports(hosts_and_ports_to_close)
        return False


def kill_open5gs_services():
    services = [
        "open5gs-mmed",
        "open5gs-sgwcd",
        "open5gs-smfd",
        "open5gs-amfd",
        "open5gs-sgwud",
        "open5gs-upfd",
        "open5gs-hssd",
        "open5gs-pcrfd",
        "open5gs-nrfd",
        "open5gs-ausfd",
        "open5gs-udmd",
        "open5gs-udrd",
        "open5gs-scpd",
        "open5gs-pcfd",
        "open5gs-nssfd",
        "open5gs-bsfd",
    ]

    for service in services:
        command = f"sudo pkill -9 {service}"
        subprocess.run(command, shell=True)

    logging.info("Open5GS services terminated.")


def kill_srsenb_services():
    services = [
        "srsenb",
    ]

    for service in services:
        command = f"sudo pkill -9 {service}"
        subprocess.run(command, shell=True)

    logging.info("srsenb services terminated.")


def all_termination(logcat, tcpdump, srsgnb, open5gs):
    # No need of teminating srsgnb and open5gs saperately, killing function doing it. also no need of port closing.
    kill_srsenb_services()
    kill_open5gs_services()
    logcat.terminate()
    tcpdump.terminate()


############################
# MAIN FUNCTION
############################

# queue for all test cases
queue = []
test_directory = ''
kill_srsenb_services()
kill_open5gs_services()
if test_type == 'nas':
    test_directory = "./Test_nas"
    # aggregated log for whether tests are successful
    result_log_path = "./" + time.asctime(time.localtime(time.time())) + "_NAS.txt"
else:
    test_directory = "./Test_rrc"
    result_log_path = "./" + time.asctime(time.localtime(time.time())) + "_RRC.txt"

result_directories = create_folders(test_type)

if test_type == 'nas':
    [adb_log_directory, amf_log_directory, enb_log_directory, pcap_file_directory] = result_directories
else:
    [adb_log_directory, amf_log_directory, enb_log_directory, pcap_file_directory, rrc_file_directory] = result_directories
    
for subdir, dirs, files in os.walk(test_directory):
    for file in sorted(files):
        file_path = os.path.join(subdir, file)
        f_name = os.path.basename(file_path)
        file_name = f_name[:-5]  # removing ".json" from the file name
        queue.append([file_name, 0])

logging.debug("finished parsing test cases")

if test_type == 'nas':
    logging.info("starting NAS testing")
else:
    logging.info("starting RRC testing")

while len(queue) > 0:
    [file_name, fail_count] = queue.pop(0)
    # continue to next element if current test fails 3 times
    if fail_count >= FAILED_TEST_RETRY:
        continue

    amf_log_file_path = amf_log_directory + "/" + file_name + "_amf_log.txt"
    enb_log_file_path = enb_log_directory + "/" + file_name + "_enb_log.txt"

    # open5gs
    
    if test_type == 'nas':
            open5gs_command = [
            "sudo",
            "-S",
            "./open5gs/build/tests/app/5gc",
            "-n",
            "./Test_nas/" + file_name + ".json",
    ]
    else:    
        open5gs_command = [
            "sudo",
            "-S",
            "./open5gs/build/tests/app/5gc",
            "-n",
            "./Test_nas/test1.json",
    ]
    with open(amf_log_file_path, "w") as log_file:
        open5gs = subprocess.Popen(
            open5gs_command,
            preexec_fn=os.setsid,
            stdin=subprocess.PIPE,
            # stdout=subprocess.PIPE,
            stdout=log_file,
            stderr=subprocess.PIPE,
        )
        open5gs.stdin.close()
        time.sleep(1)  # very important

    # srsRAN
    
    
    
    srsran_command = [
        "sudo",
        "-S",
        "./srsRAN/build/srsenb/src/srsenb",
        "configFiles/enb.conf",
    ]
    with open(enb_log_file_path, "w") as log_file:
        srsgnb = subprocess.Popen(
            srsran_command,
            preexec_fn=os.setsid,
            stdin=subprocess.PIPE,
            # stdout=subprocess.PIPE,
            stdout=log_file,
            stderr=subprocess.PIPE,
        )
    if test_type=='rrc':
    	rrc_command = 'test ./Test_rrc/'+ file_name + '.json\n'
    	srsgnb.stdin.write(rrc_command.encode())
    srsgnb.stdin.close()
    time.sleep(1)

    # TCPdump
    tcpdump_command = [
        "sudo",
        "tcpdump",
        "-i",
        "any",
        "-w",
        pcap_file_directory + "/" + file_name + ".pcap",
        "proto",
        "\\sctp",
    ]
    tcpdump = subprocess.Popen(
        tcpdump_command,
        preexec_fn=os.setsid,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tcpdump.stdin.close()

    logcat_command = ["sudo", "adb", "logcat", "-b", "radio"]
    with open(adb_log_directory + "/" + file_name + "_adb_log.txt", "w") as log_file:
        logcat = subprocess.Popen(
            logcat_command,
            preexec_fn=os.setsid,
            stdin=subprocess.PIPE,
            stdout=log_file,
            stderr=subprocess.PIPE,
        )
        logcat.stdin.close()
    # TODO: if NG connection fails, stop the following testing
    # start_time = time.time()
    logging.debug("\n-----Toggling window start--------\n\n")
    logging.info(file_name +" ----- failed %s times.\n", fail_count)

    result = False
    for i in range(AIRPLANE_TOGGLE_NUMBER):

        logging.info("\n")
        logging.info("-----Toggling number  = %s\n", i+1)
        logging.info("\n")

        device_toggling()

        # log result and terminate
        if test_type == 'nas':
            result = get_result(amf_log_file_path, file_name)
            if result:
            	all_termination(logcat, tcpdump, srsgnb, open5gs)
            	break
        else:
            result = get_result(enb_log_file_path, file_name)
            if result:
            	srsgnb.terminate() # VERY IMPORTANT, termination and waiting needed for generating good gnb side pcap
            	time.sleep(3)  # VERY IMPORTANT,
            	all_termination(logcat, tcpdump, srsgnb, open5gs)
            	shutil.copy2('/tmp/gnb_mac.pcap', rrc_file_directory + '/gnb_'+file_name+'.pcap')
            	break
    
    else: #  FOR-ELSE if all rrc itration fails, if just copy the final gnb pcap, we need not this functionality for nas test case because we are not coping anything during NAS test.
        if test_type == 'rrc': 
            srsgnb.terminate() 
            time.sleep(3)  
            all_termination(logcat, tcpdump, srsgnb, open5gs)
            shutil.copy2('/tmp/gnb_mac.pcap', rrc_file_directory + '/gnb_'+file_name+'.pcap')
        

    if not result:
        print("---------------------------")
        print(file_name + " was not invoked!")
        log_result(file_name, "not invoked")
        print("---------------------------")
        # add test to queue
        queue.append([file_name, fail_count + 1])
        all_termination(logcat, tcpdump, srsgnb, open5gs)
        #close_ports(hosts_and_ports_to_close)
        
if test_type == 'nas':
    logging.info("NAS tests finished")
else:
    logging.info("RRC tests finished")
