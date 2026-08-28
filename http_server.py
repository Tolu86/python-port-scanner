from http.server import HTTPServer, BaseHTTPRequestHandler


HOST = "127.0.0.1"
PORT = 9998


class TestHandler(BaseHTTPRequestHandler):

    server_version = "PortScannerLab/1.0"

    def do_HEAD(self):

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/plain"
        )

        self.end_headers()

    def do_GET(self):

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/plain"
        )

        self.end_headers()

        self.wfile.write(
            b"Port Scanner HTTP Lab"
        )

    def log_message(
        self,
        format,
        *args
    ):

        print(
            f"HTTP request: {format % args}"
        )


server = HTTPServer(
    (HOST, PORT),
    TestHandler
)

print(
    f"HTTP test server running on "
    f"http://{HOST}:{PORT}"
)

server.serve_forever()