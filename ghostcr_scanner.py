from scapy.all import *
import argparse
import socket
import sys
import threading
from queue import Queue
from datetime import datetime

conf.verb=0
print_lock=threading.Lock()

def get_arguments():
	parser = argparse.ArgumentParser(description="GhostCr Scanner - Advanced Network Vulnerability Scanner")
	parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP Address")
	parser.add_argument("-p", "--port", dest="port", required=True, help="Single port (80) or range (20-100)")
	parser.add_argument("-m","--mode", dest="mode", default="syn", choices=["syn","xmas", "fin", "null"], help="Scan Mode: syn, xmas, fin, null")
	parser.add_argument("-th", "--threads", dest="threads", default=20, type=int, help="Number of threads (Default: 20)")
	return parser.parse_args()

def parse_ports(port_str):
	if "-" in port_str:
		start, end = port_str.split("-")
		return range(int(start), int(end) + 1)
	else:
		return [int(port_str)]


def get_banner(ip,port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(2)
		s.connect((ip,port))

		payload = b'HEAD / HTTP/1.0\r\n\r\n'
		s.send(payload)

		banner= s.recv(1024)
		s.close()

		if banner:
			with print_lock:
				print(f"  [!] BANNER: {banner.decode(errors='ignore').splitlines()[0]}")
	except:
		pass

def scan_syn(ip, port):
	syn_packet= IP(dst=ip) / TCP(dport=port, flags="S")
	resp= sr1(syn_packet, timeout=1, verbose=0)

	if resp is not None and resp.haslayer(TCP):
		if resp.getlayer(TCP).flags== 0x12: #SYN-ACK
			rst_pkt= IP(dst=ip)/TCP(dport=port, flags="R", seq=resp.ack) #rst
			send(rst_pkt, verbose=0)
			with print_lock: 
				print(f"[+] Port {port}: OPEN")

			get_banner(ip,port) #get the banner


def inverse_scan(ip,port, flags_scan, name_scan): 
	packet= IP(dst=ip) / TCP(dport=port,flags=flags_scan)
	resp= sr1(packet, timeout=1, verbose=0)

	if resp is None:
		with print_lock:
			print(f"[+] Port {port}: OPEN o FILTERED ({name_scan})")
	elif resp.haslayer(TCP) and resp.getlayer(TCP).flags==0x14: #RST
		pass

def worker(ip, mode): 
	while True:
		try:
			port = port_queue.get(timeout=1)
		except:
			break 

		try:
			if mode == "syn":
				scan_syn(ip, port)
			elif mode == "xmas":
				inverse_scan(ip, port, "FUP", "XMAS")
			elif mode == "fin":
				inverse_scan(ip, port, "F", "FIN")
			elif mode == "null":
				inverse_scan(ip, port, 0, "NULL")
		except Exception as e:
			pass

		port_queue.task_done()

port_queue = Queue()

if __name__=="__main__":
	args = get_arguments()
	mode = args.mode.lower()
	port_list = parse_ports(args.port)

	print(f"\n[*] Executing GhostCr Scanner on {args.target}...")
	print(f"[*] Mode: {mode.upper()} | Threads: {args.threads}")
	print(f"[*] Scanning {len(port_list)} ports...\n")

	start_time = datetime.now()

	for port in port_list:
		port_queue.put(port)
	
	num_threads = min(args.threads, len(port_list))

	for _ in range(num_threads):
		t = threading.Thread(target=worker, args=(args.target, mode))
		t.daemon = True
		t.start()

	port_queue.join()

	end_time = datetime.now()
	print(f"\n[*] Scan finished in {end_time - start_time}")
