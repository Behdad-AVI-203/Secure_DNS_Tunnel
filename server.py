from dnslib import DNSRecord, DNSHeader, RR, A
from dnslib.server import DNSServer
import config
import base64
from crypto_module import decrypt 

class TunnelResolver:
    def __init__(self):
        self.buffer = {}
        self.next_expected_seq = 0

        self.output_file = None 
        print("Server initialized. Waiting for metadata...")

    def reassemble_file(self):

        if self.output_file is None:
            return

        while self.next_expected_seq in self.buffer:
            data = self.buffer.pop(self.next_expected_seq)
            with open(self.output_file, "ab") as f:
                f.write(data)
            print(f"[+] Wrote chunk {self.next_expected_seq} to file: {self.output_file}")
            self.next_expected_seq += 1

    def resolve(self, request, handler):
        qname = request.q.qname

        if qname.idna().rstrip('.').endswith(config.TUNNEL_DOMAIN):
            subdomains_str = qname.idna().replace('.' + config.TUNNEL_DOMAIN, '')
            full_encoded_data = "".join(reversed(subdomains_str.split('.')))
            
            try:
                padding_needed = 8 - (len(full_encoded_data) % 8)
                full_encoded_data += '=' * padding_needed
                encrypted_data = base64.b32decode(full_encoded_data)
                decrypted_packet = decrypt(encrypted_data, config.AES_KEY)

                if decrypted_packet:
                    packet_type = decrypted_packet[0:1]

                    if packet_type == b'\x00': 
                        filename_len = int.from_bytes(decrypted_packet[1:2], 'big')
                        filename = decrypted_packet[2:2+filename_len].decode('utf-8')
                        self.output_file = f"received_files/{filename}"

                        with open(self.output_file, "wb") as f:
                            f.write(b'')
                        print(f"[+] Metadata received. Output file set to: {self.output_file}")

                    elif packet_type == b'\x01': 
                        if self.output_file is None:
                            print("[!] Data packet received before metadata. Ignoring.")
                        else:
                            seq_num = int.from_bytes(decrypted_packet[1:5], 'big')
                            data = decrypted_packet[5:]
                            print(f"[*] Received data chunk with seq: {seq_num}")
                            self.buffer[seq_num] = data
                            self.reassemble_file()
                    
                    elif packet_type == b'\x02': 
                        print(f"[+] EOF packet received. File transfer for {self.output_file} is complete.")

                        self.__init__()

            except Exception as e:
                print(f"[!] Error processing packet: {e}")

            reply = request.reply()
            reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=60))
            return reply
        
        return request.reply()

print(f"Starting DNS Server on {config.SERVER_IP}:{config.DNS_PORT} for domain {config.TUNNEL_DOMAIN}...")
server = DNSServer(TunnelResolver(), port=config.DNS_PORT, address=config.SERVER_IP)
server.start()