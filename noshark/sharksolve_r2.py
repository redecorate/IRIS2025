import sys

def parse_packets():
    segments = {}

    for line_num, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line or line.startswith("Data:"):
            continue  

        try:
            packet_bytes = bytes.fromhex(line)
        except ValueError:
            continue

        if len(packet_bytes) < 34:  #ethernet (14) + IP (20)
            continue

        eth_length = 14
        eth_type = packet_bytes[12:14]
        if eth_type != b'\x08\x00':
            continue  

        ip_header_start = eth_length
        ip_version_ihl = packet_bytes[ip_header_start]
        ip_version = ip_version_ihl >> 4
        if ip_version != 4:
            continue

        ip_ihl = ip_version_ihl & 0x0F
        ip_header_length = ip_ihl * 4
        if len(packet_bytes) < eth_length + ip_header_length + 20:
            continue

        ip_header = packet_bytes[ip_header_start:ip_header_start + ip_header_length]

        #(bytes 2-3)
        total_length = int.from_bytes(ip_header[2:4], byteorder='big')
        if total_length < ip_header_length:
            continue
      
        tcp_header_start = eth_length + ip_header_length
        tcp_header = packet_bytes[tcp_header_start:tcp_header_start + 20]
        tcp_data_offset_reserved = tcp_header[12]
        tcp_data_offset = (tcp_data_offset_reserved >> 4) & 0x0F
        tcp_header_length = tcp_data_offset * 4

        if len(packet_bytes) < tcp_header_start + tcp_header_length:
            continue

        #(bytes 4-7 of TCP header)
        seq_num = int.from_bytes(tcp_header[4:8], byteorder='big')

        payload_start = tcp_header_start + tcp_header_length
        payload = packet_bytes[payload_start:total_length + eth_length]

        if not payload:
            continue

        segments[seq_num] = payload

    return segments

def reassemble_payload(segments):
    if not segments:
        return b''

    sorted_seqs = sorted(segments.keys())
    reassembled = bytearray()

    expected_seq = sorted_seqs[0]
    for seq in sorted_seqs:
        payload = segments[seq]
        if seq > expected_seq:
            gap_size = seq - expected_seq
            reassembled.extend(b'\x00' * gap_size)
        elif seq < expected_seq:
            overlap = expected_seq - seq
            if overlap < len(payload):
                payload = payload[overlap:]
            else:
                continue

        reassembled.extend(payload)
        expected_seq = seq + len(payload)

    return bytes(reassembled)

def extract_jpeg(data):
    start_marker = b'\xff\xd8'
    end_marker = b'\xff\xd9'

    start_index = data.find(start_marker)
    if start_index == -1:
        return None

    end_index = data.find(end_marker, start_index)
    if end_index == -1:
        return None

    end_index += 2 

    jpeg_data = data[start_index:end_index]
    return jpeg_data

def main():
    segments = parse_packets()
    reassembled = reassemble_payload(segments)
    jpeg_data = extract_jpeg(reassembled)
    if jpeg_data:
        with open("reconstructed.jpg", "wb") as f_out:
            f_out.write(jpeg_data)
        print("wrote reconstructed.jpg")
    else:
        print("failure to extract JPEG data.")

if __name__ == "__main__":
    main()
