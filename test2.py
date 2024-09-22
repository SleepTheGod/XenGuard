import requests
import pymysql
import click
from bs4 import BeautifulSoup
from sqlalchemy import create_engine

@click.command()
@click.option('--url', prompt='XenForo site URL', help='The URL of the XenForo site to test.')
@click.option('--db-host', prompt='Database Host', help='The database host for the XenForo installation.')
@click.option('--db-user', prompt='Database Username', help='The database username for XenForo.')
@click.option('--db-pass', prompt='Database Password', hide_input=True, help='The database password.')
@click.option('--db-name', prompt='Database Name', help='The XenForo database name.')
def xenforo_sqli_defense(url, db_host, db_user, db_pass, db_name):
    """Tool for testing SQL injection vulnerabilities on XenForo sites."""
    print(f"\nTesting SQL Injection Defense for XenForo site: {url}\n")

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

    # Perform SQL Injection Defense checks
    try:
        perform_sqli_defense_tests(db)
    except Exception as e:
        print(f"Error during SQL Injection testing: {e}")
    finally:
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
    connection = pymysql.connect(
        host=host,
        user=user,
        password=password,
        db=dbname,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection


def perform_sqli_defense_tests(db):
    """Perform basic SQL injection defense tests."""
    with db.cursor() as cursor:
        # Example of safe querying using parameterized queries
        table_check = "SHOW TABLES LIKE %s"
        cursor.execute(table_check, ('xf_user',))
        result = cursor.fetchone()
        if result:
            print("Test 1: 'xf_user' table found. Database looks good.")
        else:
            print("Test 1: 'xf_user' table not found. Check the database structure.")

        # Example test for SQL injection - trying an unsafe query
        # This is just for demo purposes - you should NEVER run this in production!
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
    xenforo_sqli_defense()
