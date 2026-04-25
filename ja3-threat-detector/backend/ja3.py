import hashlib

def parse_list(field):
    if not field:
        return []
    return [str(x) for x in field.split(",")]

def compute_ja3_from_packet(packet):
    try:
        tls = packet.tls

        version = str(tls.handshake_version)

        # Cipher Suites
        ciphers = parse_list(getattr(tls, "handshake_ciphersuites", ""))

        # Extensions
        extensions = parse_list(getattr(tls, "handshake_extensions_type", ""))

        # Supported Groups (Elliptic Curves)
        curves = parse_list(getattr(tls, "handshake_extensions_supported_group", ""))

        # EC Point Formats
        ec_formats = parse_list(getattr(tls, "handshake_extensions_ec_point_format", ""))

        ja3_string = f"{version},{'-'.join(ciphers)},{'-'.join(extensions)},{'-'.join(curves)},{'-'.join(ec_formats)}"

        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        return ja3_string, ja3_hash

    except Exception:
        return None, None