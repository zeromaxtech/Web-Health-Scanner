import ssl
import socket
from datetime import datetime


def check_ssl_certificate(url: str) -> dict:
    result = {
        "url":url,
        "valid":False,
        "issuer":None,
        "expires_on":None,
        "days_until_expiry":None,
        "error":None
    }
    try:
        hostname = url.replace("https://","").replace("http://","").split("/")[0]
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expiry_str =cert["notAfter"]
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        
        days_left = (expiry_date - datetime.utcnow()).days

        result["valid"] = True
        result["issuer"] = dict(x[0] for x in cert["issuer"])
        result["expires_on"] = expiry_date.strftime("%Y-%m-%d")
        result["days_until_expiry"] = days_left

    except socket.timeout:
        result["error"] = "connection timed out"
    except socket.gaierror:
        result["error"] = "Could not resolve hostname"
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verfication failed: {str(e)} "
    except Exception as e:
        result["error"] = str(e)
    
    return result