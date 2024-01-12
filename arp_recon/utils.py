import netifaces

class darkcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def colorize(string, alert):
    bcolors = darkcolours
    color = {
        'error':    bcolors.FAIL + string + bcolors.ENDC,
        'warning':  bcolors.WARNING + string + bcolors.ENDC,
        'ok':       bcolors.OKGREEN + string + bcolors.ENDC,
        'info':     bcolors.OKBLUE + string + bcolors.ENDC,
        'magenta':  bcolors.MAGENTA + string + bcolors.ENDC,
        'cyan' : bcolors.CYAN + string + bcolors.ENDC,
        'deprecated': string # No color for deprecated headers or not-an-issue ones
    }
    return color[alert] if alert in color else string

def name_of_active_interface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

def is_arp(packet):
    return packet[12:14] == b'\x08\x06'

def get_active_args(args):
    active_args = [arg for arg in vars(args) if getattr(args, arg) is not None]
    return ', '.join(active_args) if active_args else 'without arguments'

def banner(args):
    print("")
    print("=" * 58)
    print(colorize("                           ARPRecon","cyan"))
    print("-" * 58)
    print(" Tool designed for monitoring and securing networks")
    print(" against ARP-related vulnerabilities and threats.")
    print("-" * 58)
    print(f' {colorize(get_active_args(args),"magenta")}')
    print("=" * 58)
    print("")
    
def is_packet_suspicious(packet):
    # Logique simplifiée pour déterminer si un paquet est suspect
    return "suspicious" in packet

