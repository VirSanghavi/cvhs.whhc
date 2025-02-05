import socket
import requests
import concurrent.futures

# Common web ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 3306, 8080]

def scan_port(target, port):
    """Attempts to connect to a given port on the target."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                return f"Port {port} is OPEN"
    except:
        pass
    return None

def check_headers(target):
    """Fetches HTTP headers to look for security misconfigurations."""
    try:
        response = requests.get(f"http://{target}", timeout=3)
        headers = response.headers
        issues = []
        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options (Clickjacking risk)")
        if "X-XSS-Protection" not in headers:
            issues.append("Missing X-XSS-Protection (Cross-site scripting risk)")
        if "Content-Security-Policy" not in headers:
            issues.append("Missing Content-Security-Policy (Mitigates XSS and data injection attacks)")
        if "Server" in headers:
            issues.append(f"Server reveals information: {headers['Server']} (Potential fingerprinting risk)")

        return issues if issues else ["No obvious security header issues detected"]
    except requests.RequestException:
        return ["Could not fetch headers"]

def main():
    target = input("Enter the target domain or IP: ").strip()
    
    print("\nScanning common ports...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda port: scan_port(target, port), COMMON_PORTS)
    
    for result in results:
        if result:
            print(result)

    print("\nChecking HTTP headers for security issues...")
    for issue in check_headers(target):
        print(issue)

if __name__ == "__main__":
    main()
