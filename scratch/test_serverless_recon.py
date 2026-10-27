import socket
import time

def test_ping():
    print("Testing TCP Latency Ping...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    t0 = time.perf_counter()
    res = s.connect_ex(('1.1.1.1', 53))
    lat = (time.perf_counter() - t0) * 1000
    s.close()
    print(f"  Result={res}, Latency to 1.1.1.1:53 = {lat:.2f}ms")

def test_ports():
    print("Testing Port Scanner Pure Python...")
    ports = [53, 80, 443]
    open_p = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        if s.connect_ex(('1.1.1.1', p)) == 0:
            open_p.append(p)
        s.close()
    print(f"  Open ports on 1.1.1.1: {open_p}")

if __name__ == '__main__':
    test_ping()
    test_ports()
