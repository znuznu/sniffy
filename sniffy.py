import signal
import sys
import socket
import struct
import argparse
import binascii

DEFAULT_PORTS = [80, 443]
DEFAULT_PROTOCOLES = [6, 17]

class EthernetFrame:
	def __init__(self, source, destination, ethtype, bytes_payload):
		self.source = source
		self.destination = destination
		self.ethtype = socket.htons(ethtype)
		self.bytes_payload = bytes_payload

	def __str__(self):
		title = '[+] Ethernet frame [+]'
		src = 'Source: ' + self.source
		dest = 'Destination: ' + self.destination
		etht = 'EthType: ' + str(self.ethtype) 
		return '\n'.join([title, src, dest, etht]) + '\n'

class IPPacket:
	def __init__(self, version, ttl, protocole, source, destination, bytes_payload):
		self.version = version
		self.ttl = ttl
		self.protocole = protocole
		self.source = source
		self.destination = destination
		self.bytes_payload = bytes_payload

	def __str__(self):
		title = '[+] IP packet [+]'
		vrs = 'Version: ' + str(self.version)
		ttl = 'TTL: ' + str(self.ttl)
		prt = 'Protocole: ' + str(self.protocole)
		src = 'Source: ' + self.source
		dest = 'Destination: ' + self.destination
		return '\n'.join([title, vrs, ttl, prt, src, dest]) + '\n'

class Segment:
	def __init__(self, source_port, destination_port, bytes_payload):
		self.source_port = source_port
		self.destination_port = destination_port
		self.bytes_payload = bytes_payload

class TCPSegment(Segment):
	def __init__(self, source_port, destination_port, bytes_payload, sequence_number, acknowledgement_number):
		Segment.__init__(self, source_port, destination_port, bytes_payload)
		self.sequence_number = sequence_number
		self.acknowledgement_number = acknowledgement_number

	def __str__(self):
		title = '[+] TCP Segment [+]'
		srcp = 'Source port: ' + str(self.source_port)
		dstp = 'Destination port: ' + str(self.destination_port)
		sqn = 'Sequence number: ' + str(self.sequence_number)
		acknldt = 'Acknowledgement: ' + str(self.acknowledgement_number)
		pld = '\n\nPayload: \n' + dump(self.bytes_payload)
		return '\n'.join([title, srcp, dstp, sqn, acknldt]) + pld

class UDPSegment(Segment):
	def __init__(self, source_port, destination_port, bytes_payload):
		Segment.__init__(self, source_port, destination_port, bytes_payload)

	def __str__(self):
		title = '[+] UDP Segment [+]'
		srcp = 'Source port: ' + str(self.source_port)
		dstp = 'Destination port: ' + str(self.destination_port)
		pld = '\n\nPayload: \n' + dump(self.bytes_payload)
		return '\n'.join([title, srcp, dstp]) + pld

def dump(source):
	"""Convert bytes ~> hex ~> utf-8 in a Wireshark style."""
	result = []
	source_str = str(source)
	for i in range(0, len(source_str), 16):
		part = source_str[i:i+16]
		hexa_list = ['%02X' % ord(c) for c in part]
		hexa = ''.join(hexa_list)
		readable = binascii.unhexlify(hexa).decode('utf-8')
		hexa = ' '.join(hexa_list)
		result.append('{:04d}   {:<48}    {}\n'.format(i, hexa, readable))
	return ''.join(result)

def translate_MAC(addr):
	"""Translate bytes MAC address to human readable address (formatted)."""
	return ':'.join(map('{:02x}'.format, addr))

def translate_IP(addr):
	"""Translate bytes IP address to human readable address (formatted)."""
	return '.'.join(map(str, addr))

def unpack_ethernet_frame(frame):
	source, destination, eth_type = struct.unpack('!6s6sH', frame[:14])
	return EthernetFrame(translate_MAC(source), translate_MAC(destination), eth_type, frame[14:])

def unpack_IP_packet(packet):
	ip_version = packet[0] >> 4
	ip_header_length = (packet[0] & 15) * 4
	ttl, ip_protocole, ip_source, ip_destination = struct.unpack('!8xBB2x4s4s', packet[:20])
	return IPPacket(ip_version, ttl, ip_protocole, translate_IP(ip_source), translate_IP(ip_destination), packet[ip_header_length:])

def unpack_TCP_segment(segment):
	source_port, destination_port, sequence_number, acknowledgement_number = struct.unpack('!HHLL', segment[:12])
	return TCPSegment(source_port, destination_port, segment[28:], sequence_number, acknowledgement_number)

def unpack_UDP_segment(segment):
	source_port, destination_port = struct.unpack('!HH', segment[:4])
	return UDPSegment(source_port, destination_port, segment[8:])

def print_init(protocoles, ports):
	print('[Started] Sniff initialized' +
	' Protocoles ' + ' '.join(list(map(str, protocoles))) +
	' Ports ' + ' '.join(list(map(str, ports))))

def init(protocoles, ports):
	print_init(protocoles, ports)
	sniffy = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	protocoles_dict = {
		6: unpack_TCP_segment,
		17: unpack_UDP_segment
	}

	while True:
		packet = sniffy.recvfrom(65565)
		bytes_ethernet_frame = packet[0]
		ethernet_frame = unpack_ethernet_frame(bytes_ethernet_frame)

		if ethernet_frame.ethtype == 8: # IP only
			ip_packet = unpack_IP_packet(ethernet_frame.bytes_payload)
			transport_protocole = ip_packet.protocole
			if transport_protocole in protocoles:
				segment = protocoles_dict[transport_protocole](ip_packet.bytes_payload)
				if segment.source_port in ports or segment.destination_port in ports:
					print(ethernet_frame)
					print(ip_packet)
					print(segment)
					print('+' + ' -' * 36 + ' +\n')

def get_parser():
    parser = argparse.ArgumentParser(description='A simple & raw python network sniffer (TCP/UDP) for Linux systems.')
    parser.add_argument(
	'-t',
	'--transport',
	nargs='+',
	help='transport protocoles ID (6=TCP, 17=UDP)',
	choices=DEFAULT_PROTOCOLES,
	default=DEFAULT_PROTOCOLES,
	type=int,
	dest='protocoles'
    )

    parser.add_argument(
	'-p',
	'--port',
	nargs='+',
	help='source port(s)',
	default=DEFAULT_PORTS,
	type=int,
	dest='ports'
    )

    return parser

def signal_handler(signal, frame):
	sys.exit(0)

def main():
	signal.signal(signal.SIGINT, signal_handler)
	parser = get_parser()
	args = parser.parse_args()
	ports = args.ports
	protocoles = args.protocoles
	init(protocoles, ports)

if __name__ == "__main__":
	main()
