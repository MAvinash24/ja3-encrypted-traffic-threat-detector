import hashlib

def safe_get(obj, field):
    try:
        return getattr(obj, field)
    except AttributeError:
        return None

def split_fields(field):
    if not field:
        return []
    return str(field).split(",")

def compute_ja3_from_packet(packet):
    try:
        if not hasattr(packet, "tls"):
            return None, None

        tls = packet.tls

        # TLS version
        version = safe_get(tls, "handshake_version")
        if not version:
            return None, None

        # Cipher suites (important)
        ciphers = safe_get(tls, "handshake_ciphersuites")
        if not ciphers:
            return None, None
        ciphers = split_fields(ciphers)

        # Extensions
        extensions = safe_get(tls, "handshake_extensions_type")
        extensions = split_fields(extensions)

        # Supported groups (elliptic curves)
        curves = safe_get(tls, "handshake_extensions_supported_group")
        curves = split_fields(curves)

        # EC point formats
        ec_formats = safe_get(tls, "handshake_extensions_ec_point_format")
        ec_formats = split_fields(ec_formats)

        # Build JA3 string
        ja3_string = (
            f"{version},"
            f"{'-'.join(ciphers)},"
            f"{'-'.join(extensions)},"
            f"{'-'.join(curves)},"
            f"{'-'.join(ec_formats)}"
        )

        # Generate hash
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        return ja3_string, ja3_hash

    except Exception as e:
        print("JA3 ERROR:", e)
        return None, None
