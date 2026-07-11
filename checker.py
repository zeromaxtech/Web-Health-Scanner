import requests
import time
import json
import sys
from ssl_checker import check_ssl_certificate
import re

def validate_url(url: str) -> tuple[bool, str]:
    if not url or not url.strip():
        return False, "URL cannot be empty"
    
    url = url.strip()
    
    if len(url) > 2048:
        return False, "URL too long"
    
    if " " in url:
        return False, "URL cannot contain spaces"
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # auto-fix missing protocol
    
    pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$')
    if not pattern.match(url):
        return False, "Invalid URL format"
    
    return True, url

def check_url_health(url: str) -> dict:
    result = {"url": url, "status_code": None, "response_time_ms": None, "reachable": False, "error": None}
    try:
        start = time.time()
        response = requests.get(url, timeout=10)
        end = time.time()
        result["status_code"] = response.status_code
        result["response_time_ms"] = round((end - start) * 1000, 2)
        result["reachable"] = True
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except requests.exceptions.ConnectionError:
        result["error"] = "Could not connect to URL"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_security_header(url: str) -> dict:
    important_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
    ]
    report = {h: False for h in important_headers}
    try:
        response = requests.get(url, timeout=10)
        for h in important_headers:
            if h in response.headers:
                report[h] = True
    except Exception as e:
        return {"error": f"Failed to check headers: {str(e)}"}
    return report


def check_redirect(url: str) -> dict:
    result = {"final_url": None, "redirect_count": 0, "forces_https": False, "error": None}
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        result["final_url"] = response.url
        result["redirect_count"] = len(response.history)
        result["forces_https"] = response.url.startswith("https://")
    except Exception as e:
        result["error"] = str(e)
    return result


def calculate_score(health, headers, ssl_info, redirect) -> int:
    score = 0
    if health["reachable"]:
        score += 2
    if ssl_info.get("valid"):
        score += 2
    if redirect.get("forces_https"):
        score += 1
    header_count = sum(1 for v in headers.values() if v is True)
    score += header_count  # up to 5
    return score  # out of 10


def build_report(url: str) -> dict:
    health = check_url_health(url)
    report = {"url": url, "health": health}

    if health["reachable"]:
        headers = check_security_header(url)
        ssl_info = check_ssl_certificate(url)
        redirect = check_redirect(url)
        report["security_headers"] = headers
        report["ssl"] = ssl_info
        report["redirect"] = redirect
        report["score"] = calculate_score(health, headers, ssl_info, redirect)
    else:
        report["score"] = 0

    return report


def print_report(report: dict):
    print(f"\n=== Report for {report['url']} ===")
    print(f"Reachable: {report['health']['reachable']} | Status: {report['health']['status_code']}")
    if report['health']['reachable']:
        print(f"Response time: {report['health']['response_time_ms']} ms")
        print("\nSecurity Headers:")
        for h, present in report["security_headers"].items():
            print(f"  {h}: {'Present' if present else 'Missing'}")
        print(f"\nSSL valid: {report['ssl']['valid']} | Expires in: {report['ssl']['days_until_expiry']} days")
        print(f"Redirect count: {report['redirect']['redirect_count']} | Forces HTTPS: {report['redirect']['forces_https']}")
    print(f"\nOverall Score: {report['score']}/10")


def save_report(report: dict, filename: str = "report.json"):
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved to {filename}")


if __name__ == "__main__":
    raw_url = sys.argv[1] if len(sys.argv) > 1 else input("enter the url to test: ")
    
    valid, result = validate_url(raw_url)
    if not valid:
        print(f"Error: {result}")
        sys.exit(1)
    
    url = result
    report = build_report(url)
    print_report(report)
    save_report(report)