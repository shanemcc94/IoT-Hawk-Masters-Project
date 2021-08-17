#!/usr/bin/python3
"""
    IoTHawk Network Hardening

    Name: Shane McCausland
    ID: R00206886
"""
import argparse
import logging
import telnetlib
import getpass
import paramiko
import requests
from colorama import init, Fore
from paramiko import SSHClient

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP

tn = 0
list_of_ips = 0
file_IP = 0
ip = 0
splitlist = 0
# initialize colorama
init()
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE


def help():
    # Prints out usage of script, called when 0 CLA
    print("""
----------------------Help Function Accessed----------------------
    Usage: iot_hawk.py [-h] [-L | -t T] -p P  -f F
    arguments:
        -h, --help            Show this help message and exit

        -L, --Local           Local Scan Switch:
                                            Indicates that the network scan will be carried out on 
                                            IPs on the active interface. Used instead of -t T


        -t T                  Filename for IP Addresses:  
                                            Used instead of -L which scans for IP's on active interface

        -p P                  Ports to Scan:                                            
                                            List of comma seperated integers to be used as ports for scanning
                                            Port 22 and 23 are always checked by default if not provided as CLA                                                                                                                 


        -f F                  Filename containing list of login credentials
                                            Username and password combination file in the form "username:password" 
                                             is used to attempt logging into ssh,telnet & web service



        sample usage:./iot_hawk.py -L -p 22,23,24,80,8888 -f credentialfile.txt 
        sample usage:./iot_hawk.py -t ip_addresses.txt -p 22,23,24,80,8888 -f credentials.txt
    """)
    exit()


def menu(vuln_host, vuln_username, vuln_passw, vuln_TN, vuln_SSH, vuln_WEB):
    print("\n______________________Choose 1 Defensive Measure for: " + vuln_host + "____________________________\n")

    print(f"{GREEN}\t\t[+] The Host: {vuln_host} has been found to be a vulnerable IoT device.\n")

    print(f"\t\t\t{GREEN}[-] Port Scan on port 22 has been found to be\n\t\t\t open and SSH-able with the provided "
          f"Credentials.{RESET}\n")

    print(
        f"\t\t\t{GREEN}[-] Port Scan on port 23 has been found to be\n\t\t\t open and Telnet-able with the provided "
        f"Credentials.{RESET}\n")

    hardening_choice = input(f"""
                   {BLUE}[1] Perform Device Hardening on {vuln_host}.{RESET}\n
                   {BLUE}[2] Proceed to next device.{RESET}\n
                   {BLUE}[q] Quit Application.{RESET}\n
                   {BLUE}Please enter your choice:{RESET}""")
    print("\n\n_________________________________________________________________________________________________")

    if hardening_choice == "1":
        device_harden(vuln_host, vuln_username, vuln_passw)

    elif hardening_choice == "2" or hardening_choice == "2":
        return

    elif hardening_choice == "Q" or hardening_choice == "q":
        sys.exit()
    else:
        print(
            f"\t\t{RED}[!] You must only select either 1, 2, 3 or q/Q\n\t\tPlease try again {RESET}\n ")
        time.sleep(2)
        menu(vuln_host, vuln_username, vuln_passw, vuln_TN, vuln_SSH, vuln_WEB)


def read_ip_list(ip_file):
    # Function should open file and read contents into a list where each element is an IP
    # Return List
    ip_list = []
    try:
        with open(ip_file) as f:
            ip_list = f.read().splitlines()
        f.close()
    except IOError:
        print("File Not Accessible")
    return ip_list
    pass


def local_network_scan(ip_to_scan):
    """
    Performs a network scan by sending ICMP requests to an IP address or a range of IP addresses.
    Args:
        ip_to_scan (str): An IP address or IP address range to scan. For example:
                    - 192.168.1.1 to scan a single IP address
                    - 192.168.1.1/24 to scan a range of IP addresses.
    Returns:
        A list containing the hosts that responded to the request
    """
    first, second, third, fourth = str(ip_to_scan).split('.')
    ip_list = []
    local_net = first + "." + second + "." + third + "."

    print(
        '\t\t\tScanning on the range: ' + first + "." + second + "." + third + "." + "1" +
        " -> " + first + "." + second + "." + third + "." + "254")
    print("""\t\t_________________________________________________________________\n""")

    # Change 254 to 10 for shorter execution
    for ip_to_scan in range(0, 254):
        icmp_packet = IP(dst=local_net + str(ip_to_scan), ttl=20) / ICMP()
        reply = sr1(icmp_packet, timeout=2, verbose=0)
        if reply is None:
            print(f'\t\t\t\t{RED}[!] Timeout waiting for: {local_net + str(ip_to_scan)} {RESET}')
        else:
            print(f"\t\t\t\t{GREEN}[+]  {reply.src} is online. {RESET}")
            ip_list.append(reply.src)
    return ip_list


def is_reachable(ip_to_check):
    # Takes IP as parameter
    # Used to check connectivity with given IP
    # Use Scapy to send ICMP request to the IP, if reply is received return false
    # print(ip_to_check)
    response = sr1(IP(dst=ip_to_check) / ICMP(), timeout=5, verbose=0)

    if str(response) == "None":
        return False
    else:
        return True
    pass


def scan_port(ip_to_scan, port):
    # Takes IP & port number as parameter
    # Used to scan the given port using a SYN packet to see if port is open
    # Use Scapy to create an IP packet with destination of given IP
    # Then use scapy to create a TCP header containing destination of given port and set
    # flags for a SYN scan
    # Then send packet to IP if reply is received, port is open True
    # If not reply , port closed, return False
    src_port = RandShort()
    pkt = sr1(IP(dst=ip_to_scan) / TCP(sport=src_port, dport=int(port), flags="S"), timeout=1, verbose=0)
    if pkt is not None:
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 20:
                return False
            elif pkt[TCP].flags == 18:
                return True
            else:
                print(f"{BLUE}[!] TCP packet resp / filtered\n\tHOSTNAME: {ip_to_scan}:{port}\n")
        elif pkt.haslayer(ICMP):
            print(f"{BLUE}[!] ICMP resp / filtered\n\tHOSTNAME: {ip_to_scan}:{port}\n")
            return False
        else:
            print(f"{RED}[!] Unknown Response\n\tHOSTNAME: {ip_to_scan}:{port}\n")
            print(pkt.summary())
            return False
    else:
        print(f"{RED}[!] Unknown Response\n\tHOSTNAME: {ip_to_scan}:{port}\n")
        return False
    pass


def bruteforce_telnet(ip_to_scan, port, username, password):
    # Takes IP & port number, username & filename as parameter
    # Username provided by -u CLA, filename provided by -f CLA
    # Used to bruteforce the Telnet username& password for a given host
    # 1. Use Python Telnetlib to establish Telnet connection
    # 2. Attempt to log into the telnet service with the given username and pw from the file
    # 3. Detect whether or not username & pw has worked
    # 4. If working combo found return True
    # 5. If no match found return False
    # 6. Called from main if port scan finds port 23 to be open
    global tn
    try:
        tn = telnetlib.Telnet(ip_to_scan, 23, timeout=1)
        tn.read_until(b"login: ")
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        # for p in pass_list:
        tn.write(password.encode('ascii') + b"\n")
        tn.write(b"exit\n")
        answer = str(tn.read_all())
        tn.close()
        if "Last login" in answer:
            print(
                f"{GREEN}\t\t\t[+] Found combo:\n\t\t\t\tHOSTNAME: {ip_to_scan}:{port}\n\t\t\t\tUSERNAME: {username}"
                f"\n\t\t\t\t "
                f"PASSWORD: {password}{RESET}")
            return True
        elif "Login incorrect" in answer:
            print(
                f"{RED}\t\t\t\t[+] Failed combo:\n\t\t\t\tHOSTNAME: {ip_to_scan}:{port}\n\t\t\t\tUSERNAME: {username}"
                f"\n\t\t\t\t "
                f"PASSWORD: {password}{RESET}")
            return False
    except ConnectionRefusedError:
        print(
            f"{RED}\t\t\t[+] Connection Refused for:\n\t\t\t\tHOSTNAME: {ip_to_scan}:{port}{RESET}")
        tn.close()
        return False

    except socket.timeout:
        print(
            f"{RED}\t\t\t[+] Failed combo:\n\tHOSTNAME: {ip_to_scan}:{port}\n\t\t\t\tUSERNAME: {username}\n\t\t\t\t"
            f"PASSWORD: {password}{RESET}")
        tn.close()
        return False
    return False
    pass


def file2list(filename):
    pass_list = []
    try:
        pass_list = open(filename).read().splitlines()
    except IOError:
        print("File Not Accessible")
    return pass_list
    pass


def bruteforce_ssh(ip_to_bruteforce_ssh, port, username, password):
    # Takes IP & port number, username & filename as parameter
    # Username provided by -u CLA, filename provided by -f CLA
    # Used to bruteforce the SSH username& password for a given host
    # 1. Open file containing pw list
    # 2. For each pw in file attempt to create SSH with target host IP and port
    # 3. Use Python Paramiko library to establish SSH connection
    # 4. Attempt to log into the SSH service with the given username and pw from the file
    # 5. Detect whether or not username & pw has worked
    # 6. If working combo found return in True
    # 7. If no match found return False
    # 8. Should be called from main if port scan finds port 22 to be open
    client = paramiko.SSHClient()
    # add to know hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=ip_to_bruteforce_ssh, username=username, password=password, timeout=3)
    except socket.timeout:
        # this is when host is unreachable
        print(f"{RED}\t\t\t[!] Host: {ip_to_bruteforce_ssh} is unreachable, timed out.{RESET}")
        client.close()
        return False
    except paramiko.AuthenticationException:
        print(f"{RED}\t\t\t[!] Invalid credentials for {username}:{password}{RESET}")
        client.close()
        return False
    except paramiko.SSHException:
        print(f"{BLUE}\t\t\t[*] Quota exceeded, retrying with 60 second delay please wait...{RESET}")
        # sleep for a minute
        time.sleep(60)
        return bruteforce_ssh(ip_to_bruteforce_ssh, port, username, password)
    else:
        print(
            f"{GREEN}\t\t\t[+] Found combo:\n\t\t\t\tHOSTNAME: {ip_to_bruteforce_ssh}\n\t\t\t\tUSERNAME: {username}\n"
            f"\t\t\t\t "
            f"PASSWORD: {password}{RESET}")
        client.close()
        return True

    pass


def bruteforce_web(ip_to_bruteforce_web, port, username, password):
    # Takes IP & port number, username & filename as parameter
    # Username provided by -u CLA, filename provided by -f CLA
    # Used to bruteforce the web app username & password for a given host
    # 1. Open file containing pw list
    # 2. Use python requests library to send a HTTP GET request to the given IP and port
    # 3. Detect whether website exists with the previous request
    # 4. If exists attempt to bruteforce login using pw file
    # 5. If working combo found return True
    # 6. Should be called from main if port scan finds port 80, 8080 or 8888 to be open
    # php_url = "http://" + ip_to_bruteforce_web
    php_url = "http://" + ip_to_bruteforce_web + ":" + port + "/login.php"
    try:
        resp = (requests.post(php_url, {"username": username, "password": password}, timeout=1.5, verify=False))
        if resp and resp.status_code == 200:
            print(
                f"{GREEN}\t\t\t\t[+] Working combination found for web access to: \n\tHOSTNAME: {php_url}\n\t"
                f"USERNAME: {username}\n\tPASSWORD: {password}{RESET}")
            return True
        else:
            return False
    except ConnectionRefusedError:
        print(f"{RED}\t\t\t\t[!] Error Connecting{RESET}")
        return False
    except requests.exceptions.ReadTimeout:
        print(f"{RED}\t\t\t\t[!]Connection Timed out Check Client{RESET}")
        return False
    pass


def device_harden(vuln_host, vuln_username, vuln_passw):
    print("\n______________________Device Hardening Beginning for:" + vuln_host + "___________________________\n")

    ssh: SSHClient = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=vuln_host, username=vuln_username, password=vuln_passw, timeout=3)
    newpass_prompt = f"{BLUE}[+] Enter a new password to secure the device:"
    confirm_prompt = f"{BLUE}[+] Confirm Password:"
    error_prompt = f"{RED}[!] Passwords don't match, please try again:"
    vulnports_to_close = ["21", "23", "80", "8080", "8888", "48101"]
    password = getpass.getpass(newpass_prompt)
    password_again = getpass.getpass(confirm_prompt)
    while password_again != password:
        print(error_prompt)
        password = getpass.getpass(newpass_prompt)
        password_again = getpass.getpass(confirm_prompt)

    print(f"{MAGENTA}\t\t[+] Performing the following defensive measures:")
    print(f"{GREEN}\t\t[-] Changing SSH password. {RESET}")
    stdin, stdout, stderr = ssh.exec_command('sudo passwd')
    stdin.write(password + '\n')
    stdin.write(password + '\n')
    stdin.flush()
    time.sleep(1)
    sshport = str(random.randint(1024, 32726))
    telnetport = str(random.randint(1024, 32726))
    while telnetport == sshport:
        telnetport = str(random.randint(1024, 32726))
    print(f"{GREEN}\t\t[-] Randomizing SSH port.  {RESET}")
    print(f"{BLUE}\t\t\t[+] New SSH port chosen between 1024 & 32726:  {sshport}{RESET}")
    ssh.exec_command('sudo sed -i \'s|Port 22|Port ' + sshport + '|g\' /etc/ssh/sshd_config')
    ssh.exec_command('sudo sed -i \'s|22/tcp|' + sshport + '/tcp|g\' /etc/services')
    ssh.exec_command('sudo sed -i \'s|22/udp|' + sshport + '/udp|g\' /etc/services')
    time.sleep(1)
    print(f"{GREEN}\t\t[-] Randomizing Telnet port.{RESET}")
    print(f"{BLUE}\t\t\t[+] New SSH Telnet port chosen between 1024 & 32726:  {telnetport}{RESET}")
    ssh.exec_command('sudo sed -i \'s|23/tcp|' + telnetport + '/tcp|g\' /etc/services')
    print(f"{GREEN}\t\t[-] Disabling Telnet  {RESET}")
    ssh.exec_command('sudo systemctl disable telnetd.service')
    time.sleep(1)
    print(f"{GREEN}\t\t[-] Closing Vulnerable Ports  {RESET}")
    print(f"{BLUE}\t\t\t[+] Closing Port 48101  {RESET}")
    print(f"{BLUE}\t\t\t[+] Closing Ports 21,22,23,25  {RESET}")
    print(f"{BLUE}\t\t\t[+] Closing Web Ports 80,8080,8888  {RESET}")
    for port in vulnports_to_close:
        try:
            _, stdout, stderr = ssh.exec_command('sudo kill $(sudo lsof -t -i:' + port + ') --permanent')
        except EOFError:
            break
    time.sleep(1)
    print(f"{GREEN}\t\t[-] Shutting down Web server. {RESET}")
    ssh.exec_command('sudo systemctl disable apache2 && sudo systemctl stop apache2')
    ssh.exec_command('/etc/init.d/apache2 stop --permanent')
    ssh.exec_command('sudo systemctl disable httpd')
    time.sleep(1)
    print(f"{GREEN}\t\t[-] Busybox shell made exclusive to root {RESET}")
    print(f"{GREEN}\t\t[-] Disabling SMTP {RESET}")
    ssh.exec_command('sudo /etc/init.d/sendmail stop')
    time.sleep(1)
    print(f"{GREEN}\t\t[-] Cleaning Up & Restarting Services {RESET}")
    ssh.exec_command('sudo systemctl daemon-reload')
    ssh.exec_command('sudo /etc/init.d/ssh restart')
    ssh.exec_command('sudo reboot now')
    time.sleep(1)
    print(
        f"{BLUE}\n[+] Device Hardening complete for: {vuln_host}. Returning to main menu for next vulnerable host."
        f" {RESET}")
    time.sleep(1)
    print("\n________________________________________________________________________________________________")


def main():
    global list_of_ips, file_IP, ip, splitlist
    parser = argparse.ArgumentParser()
    if len(sys.argv) == 1:
        help()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-L", "--local", help="Local Switch", action='store_true')
    group.add_argument("-t", help="Filename for IP Addresses")
    parser.add_argument("-p", help="Ports to Scan. Port 22 and 23 are always checked by default if not provided as CLA", required=True)
    parser.add_argument("-f", help="Filename Containing List of Credentials username:password", required=True)
    cl_args = parser.parse_args()

    if cl_args.local:
        print("Local Active")
        pass
    else:
        file_IP = cl_args.t
        list_of_ips = read_ip_list(file_IP)
    ports_to_scan = cl_args.p.split(",")
    if "22" not in ports_to_scan:
        ports_to_scan.append("22")
    if "23" not in ports_to_scan:
        ports_to_scan.append("23")
    file_credentials = cl_args.f
    list_of_reachable_ips = []
    list_of_reachable_ips_w_open_ports = []
    credential_list = file2list(file_credentials)
    vuln_device_str = ""
    username = ""
    password = ""
    list_of_vulnerable_devices = []

    if cl_args.local:
        if_name = get_working_if()
        source_ip = get_if_addr(if_name)
        print(
            "\n _________________Scanning for Reachable IP Addresses on Local Network:  "
            "____________________\n")
        list_of_reachable_ips = local_network_scan(source_ip)

    else:
        print(
            "\n ________________Scanning for Reachable IP Addresses from: " + file_IP
            + " ___________________\n")
        for ip in list_of_ips:
            if is_reachable(ip):
                print(f"\t\t\t{GREEN}[+] {ip} Gave a response{RESET}")
                list_of_reachable_ips.append(ip)
            else:
                print(f"\t\t\t{RED}[+] {ip} Gave no response{RESET}")
            pass
        pass
    print(
        "\n_______________________________________________________________________________________________")
    time.sleep(2)

    print("\n______________________Port Scan of Reachable IP Addresses Initiated____________________________\n")
    for ip in list_of_reachable_ips:
        for port in ports_to_scan:
            is_port_open = scan_port(ip, port)
            if is_port_open:
                list_of_reachable_ips_w_open_ports.append(ip + ":" + port)
                print(f"\t\t\t{GREEN}[+] {ip}:{port} IS OPEN{RESET}")
            else:
                print(f"\t\t\t{RED}[+] {ip}:{port} IS CLOSED{RESET}")
            pass
        pass
    pass
    print("\n________________________________________________________________________________________________")
    time.sleep(2)

    isSSH = False
    isTN = False
    isWeb = False
    for i in list_of_reachable_ips_w_open_ports:

        splitlist = i.split(":")
        if int(splitlist[1]) == 22:
            print("\n______________________Brute Force SSH Activated for: " + i + "_________________________\n")
            for credential in credential_list:
                cred_list = credential.split(':')
                username = cred_list[0]
                password = cred_list[1]
                if bruteforce_ssh(splitlist[0], splitlist[1], username, password):
                    # SSH is Vulnerable
                    isSSH = True
                    break

            print("\n________________________________________________________________________________________________")
            time.sleep(2)

        elif int(splitlist[1]) == 23:
            print("\n______________________Brute Force Telnet Activated for: " + i + "______________________\n")
            for credential in credential_list:
                cred_list = credential.split(':')
                username = cred_list[0]
                password = cred_list[1]
                if bruteforce_telnet(splitlist[0], splitlist[1], username, password):
                    isTN = True
                    break
            print("\n________________________________________________________________________________________________")
            time.sleep(2)

        elif int(splitlist[1]) == 80 or int(splitlist[1]) == 8080 or int(splitlist[1]) == 8888:
            print("\n______________________Brute Force Web Activated for: " + i + "_________________________\n")
            for credential in credential_list:
                cred_list = credential.split(':')
                username = cred_list[0]
                password = cred_list[1]
                if bruteforce_web(splitlist[0], splitlist[1], username, password):
                    isWeb = True
                    break
                else:
                    print(
                        f"{RED}\t\t\t[!] No Working combination found for web access to: \n\t\t\t\tHOSTNAME: {i}\n\t"
                        f"\t\t\tUSERNAME: "
                        f" {username}\n\t\t\t\tPASSWORD: {password}{RESET}")
            print("\n________________________________________________________________________________________________")
        if isSSH and isTN:
            vuln_device_str += splitlist[0] + ":" + username + ":" + password
            list_of_vulnerable_devices.append(vuln_device_str)
            # Reset for next host.
            vuln_device_str = ""
            isSSH = False
            isTN = False

    time.sleep(2)
    print(
        f"{GREEN}\t\t\t[!] Scanning complete for hosts provided in \n\t\t\t\tFILE: {file_IP} {RESET}"
        f"{GREEN}\n\t\t\t[!] Using the credentials provided in \n\t\t\t\tFILE: {file_credentials} {RESET}")
    for device in list_of_vulnerable_devices:
        # Each Device is in the form ip:username:password
        info_for_hardening = device.split(":")
        vuln_host = info_for_hardening[0]
        vuln_username = info_for_hardening[1]
        vuln_passw = info_for_hardening[2]
        print(f"{GREEN}\n\n\t\t\t[!] Proceeding to Device Hardening {RESET}")

        menu(vuln_host, vuln_username, vuln_passw, isSSH, isTN, isWeb)
    print(
        f"{MAGENTA}\t\t[!] Execution complete, no more hosts remaining. \n\t\t\t\t{RESET}")


if __name__ == '__main__':
    main()
