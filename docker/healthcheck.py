"""Check Nginx and the application through a container-local Unix socket."""
import http.client
import socket


def main():
    connection = http.client.HTTPConnection('localhost', timeout=4)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(4)
    try:
        connection.sock.connect('/tmp/ntwa-health.sock')
        connection.request('GET', '/healthz')
        response = connection.getresponse()
        if response.status != 200:
            raise SystemExit(f'Unhealthy application: HTTP {response.status}')
    finally:
        connection.close()


if __name__ == '__main__':
    main()
