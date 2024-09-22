import mysql.connector
import requests
import time

class XenAPI:
    def __init__(self, host, user, password, database):
        self.conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        self.cursor = self.conn.cursor(dictionary=True)

    def get_database(self):
        return self.cursor

    def quote(self, value):
        # Equivalent to SQL quoting, safely quotes the input.
        return f"'{str(value).replace('\'', '\'\'')}'"

    def has_request(self, param):
        # Replace this with actual logic, e.g., checking parameters passed to the tool
        return param in ['order_by', 'value']

    def close(self):
        self.conn.close()

class UserManager:
    def __init__(self, xenAPI):
        self.xenAPI = xenAPI
        self.limit = 10  # Adjust as needed
        self.order = 'ASC'  # Default order

    def check_order_by(self, valid_fields):
        order_by_field = 'user_id'  # Default
        return order_by_field if order_by_field in valid_fields else 'user_id'

    def get_users(self, string, order_by_field='user_id'):
        order_by_field = self.check_order_by([
            'user_id', 'message_count', 'conversations_unread', 'register_date',
            'last_activity', 'trophy_points', 'alerts_unread', 'like_count'
        ])

        query = "SELECT `user_id`, `username`"
        if self.xenAPI.has_request('order_by'):
            query += f", {self.xenAPI.quote(order_by_field)}"
        query += " FROM `xf_user`"
        if self.xenAPI.has_request('value'):
            query += f" WHERE `username` LIKE {self.xenAPI.quote(string)}"
        if self.xenAPI.has_request('order_by'):
            query += f" ORDER BY {self.xenAPI.quote(order_by_field)} {self.order}"
        if self.limit > 0:
            query += f" LIMIT {self.xenAPI.quote(self.limit)}"

        self.xenAPI.get_database().execute(query)
        results = self.xenAPI.get_database().fetchall()
        return results

    def get_group(self, group):
        query = f"""
        SELECT * FROM `xf_user_group`
        WHERE `user_group_id` = {self.xenAPI.quote(group)} 
        OR `title` = {self.xenAPI.quote(group)} 
        OR `user_title` = {self.xenAPI.quote(group)}
        """
        self.xenAPI.get_database().execute(query)
        result = self.xenAPI.get_database().fetchone()
        return result

    def get_user(self, input, fetch_options=None):
        fetch_options = fetch_options or {}
        if 'custom_field' in fetch_options:
            query = f"""
            SELECT `user_id` 
            FROM `xf_user_field_value`
            WHERE `field_id` = {self.xenAPI.quote(fetch_options['custom_field'])}
            AND `field_value` = {self.xenAPI.quote(input)}
            """
            self.xenAPI.get_database().execute(query)
            result = self.xenAPI.get_database().fetchone()

            if result and 'user_id' in result:
                input = result['user_id']

        return input

# SQL Injection Defense Test Function
def sql_injection_test(url):
    # Test payloads (common SQL injection strings)
    injection_payloads = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR ''='",
        "' OR 1=1--",
        "' OR 'a'='a",
        "' OR 'a'='a'--",
        "admin'--",
        "admin'/*",
        "admin' OR '1'='1",
    ]

    print("\n[INFO] Starting SQL Injection test...")

    for payload in injection_payloads:
        target_url = f"{url}?username={payload}"
        try:
            response = requests.get(target_url, timeout=5)
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                print(f"[WARNING] Possible SQL injection vulnerability detected with payload: {payload}")
            else:
                print(f"[SAFE] No issues detected with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to connect or timeout for payload: {payload}")

        # Sleep for a short time to avoid overwhelming the server
        time.sleep(2)

    print("[INFO] SQL Injection test completed.\n")

# Main function with prompts for the user
def main():
    print("===== XenForo SQL Injection Defense Tool =====")
    print("Warning: Only use this tool on websites you have explicit permission to test!\n")

    # Prompt for XenForo website URL
    website_url = input("Enter the URL of the XenForo website you want to test (e.g., https://example.com): ").strip()

    # Test the URL for SQL Injection vulnerabilities
    sql_injection_test(website_url)

    # Prompt for MySQL credentials for further database interaction (optional)
    use_db = input("\nWould you like to interact with the database directly (Y/N)? ").strip().lower()
    if use_db == 'y':
        host = input("MySQL Host: ").strip()
        user = input("MySQL User: ").strip()
        password = input("MySQL Password: ").strip()
        database = input("MySQL Database: ").strip()

        # Establish the XenForo API connection
        xen_api = XenAPI(host, user, password, database)
        user_manager = UserManager(xen_api)

        # Example: Get users based on a search string
        search_string = input("\nEnter a username or part of a username to search for: ").strip()
        users = user_manager.get_users(search_string)
        print("Users found:", users)

        xen_api.close()

if __name__ == "__main__":
    main()
