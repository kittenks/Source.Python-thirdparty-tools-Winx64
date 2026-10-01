import socket, struct, sys

# Minimal Source RCON client (TCP). Used only to wake/command the local test
# server while it is hibernating.
SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0


def pkt(rid, rtype, body):
    body = body.encode('utf-8', 'replace')
    payload = struct.pack('<ii', rid, rtype) + body + b'\x00\x00'
    return struct.pack('<i', len(payload)) + payload


def recv_packet(sock):
    def rd(n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise EOFError('closed')
            buf += chunk
        return buf
    size = struct.unpack('<i', rd(4))[0]
    data = rd(size)
    rid, rtype = struct.unpack('<ii', data[:8])
    body = data[8:-2].decode('utf-8', 'replace')
    return rid, rtype, body


def main(host, port, password, *commands):
    s = socket.create_connection((host, int(port)), timeout=8)
    s.settimeout(4)
    s.sendall(pkt(1, SERVERDATA_AUTH, password))
    authed = False
    try:
        while True:
            rid, rtype, body = recv_packet(s)
            if rtype == SERVERDATA_AUTH_RESPONSE:
                authed = (rid != -1)
                break
    except socket.timeout:
        pass
    print('AUTH ok=%s' % authed)
    if not authed:
        return 2
    cid = 10
    for cmd in commands:
        cid += 1
        s.sendall(pkt(cid, SERVERDATA_EXECCOMMAND, cmd))
        # sentinel to delimit the response
        sentinel_id = cid + 1000
        s.sendall(pkt(sentinel_id, SERVERDATA_RESPONSE_VALUE, ''))
        text = ''
        try:
            while True:
                rid, rtype, body = recv_packet(s)
                if rid == sentinel_id:
                    break
                text += body
        except socket.timeout:
            pass
        print('>>> %s\n%s' % (cmd, text.strip() or '(no text response)'))
    s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
