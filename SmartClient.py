#!/usr/bin/python
import sys
import socket
import ssl

hostname = sys.argv[1]
httpVersion = "HTTP/1.1"
# preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
request = "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nConnection: Keep-Alive\r\n\r\n"
SSL_PORT = 443
PORT = 80

supportsSSL = False
supportsHttp1 = False
supportsHttp2 = False
cookies = []


def parse_result(result):
    if result:
        return "yes"
    else:
        return "no"


def format_cookie(cookie):
    formattedCookie = cookie.split(":", 1)[1] + ";"
    crumbs = formattedCookie.split(";")
    reassembledCookie = ""
    reassembledCookie = reassembledCookie + "cookie name: " + crumbs[0].strip().split("=")[0]
    for crumb in crumbs:
        print(crumb.strip())
        if "Domain" in crumb:
            reassembledCookie = reassembledCookie + (", domain name: " + crumb.strip().split("=")[1])
        if "Expires" in crumb:
            reassembledCookie = reassembledCookie + (", expires time: " + crumb.strip().split("=")[1])
    if reassembledCookie != "":
        return reassembledCookie


# Check if supports https
try:
    # Try sending a secure network request to the host
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    # Offer http/1.1
    context.set_alpn_protocols(["http/1.1"])
    socketObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Wrap socket with SSL
    secureSocket = context.wrap_socket(socketObj, server_hostname=hostname)
    secureSocket.connect((hostname, SSL_PORT))
    print()
    print("---HTTPS Request Begin---")
    print(request.strip())
    print()
    secureSocket.send(request.encode())
    print("---HTTPS Request End---")
    print("HTTPS request sent. Awaiting response...")
    print()
    response = secureSocket.recv(16384)
    secureSocket.close()
    decoded = response.decode(encoding="UTF-8", errors="ignore")
    lines = decoded.strip().splitlines()
    print("---HTTPS Response---")
    for line in lines:
        # All non body lines
        if line[:1] != "<":
            print(line)
        # Check for cookies
        if "Set-Cookie" in line or "set-cookie" in line:
            cookie = format_cookie(line)
            # Check if cookie is already recorded
            if cookie not in cookies and cookie is not None:
                cookies.append(cookie)
    print()
    # Get status code from response
    statusCode = lines[0].split()[1]
    # If response is 2xx or 3xx:
    if int(str(statusCode)[:1]) == 2 or int(str(statusCode)[:1]) == 3:
        supportsSSL = True
    else:
        # Status code is not 2xx or 3xx
        supportsSSL = False
except:
    # If connection fails, SSL is not supported
    print("1. Supports of HTTPS: no")
    supportsSSL = False
    supportsHttp2 = False

# Check for HTTP1.1 support
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Connect to non-ssl-wrapped socket
    s.connect((hostname, PORT))
    print()
    print("---HTTP/1.1 Request Begin---")
    print(request.strip())
    print()
    s.send(request.encode())
    print("---HTTP/1.1 Request End---")
    print("HTTP/1.1 request sent. Awaiting response...")
    print()
    response = s.recv(16384)
    s.close()
    # Walk through response to check support
    lines = response.decode().strip().splitlines()
    print("---HTTP/1.1 Response---")
    for line in lines:
        if line[:1] != "<":
            print(line)
        if "Set-Cookie" in line or "set-cookie" in line:
            cookie = format_cookie(line)
            # Check if cookie is already recorded
            if cookie not in cookies and cookie is not None:
                cookies.append(cookie)
    print()
    statusCode = lines[0].split()[1]
    # If response is 2xx or 3xx:
    if int(str(statusCode)[:1]) == 2 or int(str(statusCode)[:1]) == 3:
        supportsHttp1 = True
    else:
        supportsHttp1 = False

# Check for HTTP2.0 support
if supportsSSL:
    # Create SSL context to wrap
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    # Offer http2
    context.set_alpn_protocols(["h2"])
    socketObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secureSocket = context.wrap_socket(socketObj, server_hostname=hostname)
    # Connect to SSL wrapped socket
    secureSocket.connect((hostname, SSL_PORT))
    protocol = secureSocket.selected_alpn_protocol()
    # Check if handshake returned http2 protocol
    if protocol is None:
        supportsHttp2 = False
    if protocol == "h2":
        supportsHttp2 = True
else:
    supportsHttp2 = False

# print results
print("---RESULTS---")
print("website: " + sys.argv[1])
print("1. Supports of HTTPS: " + parse_result(supportsSSL))
print("2. Supports of http1.1: " + parse_result(supportsHttp1))
print("3. Supports of http2: " + parse_result(supportsHttp2))
if len(cookies) > 0:
    print("4. List of cookies:")
    for cookie in cookies:
        print(cookie)
else:
    print("4. No cookies found for request.")
