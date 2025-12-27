# MITM Cookie Catcher

A proxy tool based on `mitmproxy` and `FastAPI` that intercepts HTTP traffic to capture Cookies from specific domains and provides a web management interface.

## Features

- **Domain Watchlist**: Configure which domains to capture cookies from.
- **Request-Only Capture**: Captures cookies from Request headers (avoids storing messy `Set-Cookie` attributes).
- **Web Management UI**: View captured cookies and manage settings via a browser.
- **Proxy Authentication**: Enforce Username/Password authentication for the proxy (useful for public deployment).
- **Auto-Refresh**: Live updates on the management dashboard.
- **Docker Support**: Ready for containerized deployment.

## Installation

### Local Running

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   python main.py
   ```
3. Access:
   - **Proxy**: Port `8080`
   - **UI**: [http://localhost:8081](http://localhost:8081)

### Docker Deployment

1. Build the image:
   ```bash
   docker build -t mitm-cookie .
   ```
2. Run the container:
   ```bash
   docker run -d \
     -p 8080:8080 \
     -p 8081:8081 \
     -v $(pwd)/cookies.db:/app/cookies.db \
     mitm-cookie
   ```

## Configuration

1. Open the UI at `http://localhost:8081`.
2. Add domains to watch (e.g., `baidu.com`).
3. (Optional but Recommended) Set a Proxy Username and Password in the sidebar. 
   - **Note**: If set, clients must support HTTP Basic Auth. If NOT set, the proxy is open (ensure firewall rules if on public server). 
   - *Current Logic*: The proxy will reject connections (503) if auth is not configured, to prevent accidental open proxies.

## Usage

1. Configure your client (Phone/Browser) to use the Proxy IP and Port (8080).
2. Install the mitmproxy CA certificate:
   - Visit [http://mitm.it](http://mitm.it) through the proxy.
   - Download and Trust the certificate (enable "Full Trust" on iOS).
3. Browse the target domains.
4. Cookies will appear in the UI.

## License

MIT
