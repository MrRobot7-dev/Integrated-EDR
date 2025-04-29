import pyshark
from utils.log import init_logger

# Import all protocol monitors
from modules import (
    dns_monitor,
    http_monitor,
    ftp_monitor,
    icmp_monitor,
    dhcp_monitor,
    rdp_monitor,
    smb_monitor,
    smtp_monitor,
    snmp_monitor,
    ssh_monitor,
    telnet_monitor,
    tls_monitor,
    tor_monitor
)

INTERFACE = 'Wi-Fi'

def main():
    print("[*] Starting EDR Network Filter (Full Modular)...")
    logger = init_logger()
    capture = pyshark.LiveCapture(interface=INTERFACE)

    for packet in capture.sniff_continuously():
        print("[DEBUG] Packet captured:", packet.highest_layer)
        # Pass packet and logger to each module
        dns_monitor.inspect(packet, logger)
        http_monitor.inspect(packet, logger)
        ftp_monitor.inspect(packet, logger)
        icmp_monitor.inspect(packet, logger)
        dhcp_monitor.inspect(packet, logger)
        rdp_monitor.inspect(packet, logger)
        smb_monitor.inspect(packet, logger)
        smtp_monitor.inspect(packet, logger)
        snmp_monitor.inspect(packet, logger)
        ssh_monitor.inspect(packet, logger)
        telnet_monitor.inspect(packet, logger)
        tls_monitor.inspect(packet, logger)
        tor_monitor.inspect(packet, logger)

if __name__ == '__main__':
    main()
