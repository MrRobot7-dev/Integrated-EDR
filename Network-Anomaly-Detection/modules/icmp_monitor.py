from utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "ICMP" not in pkt:
            return

        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        alert = {
            "technique_id": "T1040",
            "technique": "ICMP Tunneling or Discovery",
            "description": "ICMP packet detected - potential covert channel or ping sweep",
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

        if not is_false_positive(alert):
            log_alert(**alert)

    except Exception:
        pass
