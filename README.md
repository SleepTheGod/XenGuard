# XenGuard
```
██╗  ██╗███████╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
╚██╗██╔╝██╔════╝████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ╚███╔╝ █████╗  ██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██╔██╗ ██╔══╝  ██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██╔╝ ██╗███████╗██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
```

Made By Taylor Christian Newsome

XenGuard is a penetration testing tool designed for scanning SQL injection vulnerabilities on XenForo sites. This tool aims to assist red teamers in identifying potential security issues in web applications.

## Features
- Tests for SQL injection vulnerabilities using predefined payloads.
- Connects to the MySQL database to perform basic defense tests.
- Provides detailed feedback on vulnerability status.

## Installation
Clone the repository: 
```bash
   git clone https://github.com/SleepTheGod/XenGuard.git
```
Navigate to the project directory
```bash
cd XenGuard
```
Install the required dependencies
```bash
pip install -r requirements.txt
```
Usage
Run the main script to start testing for SQL injection vulnerabilities
```bash
python main.py
```
You will be prompted to enter the following information

XenForo site URL
Database host
Database username
Database password
Database name
Endpoint to test (e.g., /login)
Scripts
test.py: This script contains additional testing methods for SQL injection.
test2.py: This script includes alternative testing techniques.
main.py: The primary script for running the SQL injection scanner.
Contributing
Feel free to fork the repository and submit pull requests for any improvements or new features.
