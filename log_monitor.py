#!/usr/bin/env python3

#imports the libraries needed
import ssl
import smtplib
import time
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo # the library is used to make sure that all time values are in the same timezone to avoid errors

# Email config
SMTP_SERVER = "smtp.ukr.net"
SMTP_PORT = 465
EMAIL_ADDRESS = "log_monitor@ukr.net"
EMAIL_PASSWORD = "ejeSaPfrSRTafI6U"
RECIPIENT_EMAIL = "dmytrodrapei.96@gmail.com"

# Monitoring config
FAILURE_THRESHOLD = 5
MONITORING_HOURS = 1
MY_LOG_FILE_PATH = "/var/log/auth.log"
CHECK_INTERVAL = 10 # variable that defines how frequent the check for failed logins is going to be performed

# function that sends an email
def send_alert_email(failure_count):
    try:
        context = ssl.create_default_context()

        # variable for the message
        message_text = (
            f"WARNING: High number of authentication failures detected!\n\n"
            f"There have been {failure_count} failed login attempts in the past {MONITORING_HOURS} hour(s).\n"
            f"Time of alert: {datetime.now(ZoneInfo('UTC')).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

        message = MIMEText(message_text)
        message["From"] = EMAIL_ADDRESS
        message["To"] = RECIPIENT_EMAIL
        message["Subject"] = "Security Alert - Multiple Authentication Failures"

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(message)
            print("Alert email was sent successfully!")

    # handles all the errors
    except Exception as e:
        print(f"Error sending email alert: {e}")

# function that counts failures to authenticate in the last hour
def count_auth_failures(log_file_path, hours=MONITORING_HOURS):

    # variable that stores current time of the check
    current_time = datetime.now(ZoneInfo("UTC"))

    # variable that calculates the last time to check for failures
    cutoff_time = current_time - timedelta(hours=hours)

    # variable that counts the failures
    failure_count = 0

    # opens the log file that stores login details in the read mode
    with open(log_file_path, 'r') as file:
        # checks every line
        for line in file:
            try:
                # stores the string before first space in this variable, assumes that it is a time, converts it to the date format
                log_time = datetime.fromisoformat(line.split()[0])

                # checks for 2 conditions: if the time is less than 1 hour in a line and if the line contains "authentication failure"
                if log_time >= cutoff_time and "authentication failure" in line:
                    failure_count += 1

            # that line is here to make sure the script runs in case the string in the line before first space can't be converted to the date
            except (ValueError, IndexError):
                continue

    # the function returns the number of failed login attempts
    return failure_count

# main function that calls previously defined functions
def main():
    print("Starting authentication failure monitoring...")
    # variable that stores the last time an email was sent
    last_alert_time = None

    #Makes sure that the script continue to run until it is stopped by a user
    while True:
        try:
            # Check for authentication failures
            failures = count_auth_failures(MY_LOG_FILE_PATH)
            current_time = datetime.now(ZoneInfo("UTC"))

            print(f"[{current_time.strftime('%Y-%m-%d %H:%M:%S UTC')}] "
                  f"Authentication failures in the past hour: {failures}")

            # Send alert if threshold is exceeded, and we haven't sent an alert in the last hour
            if failures >= FAILURE_THRESHOLD:
                if last_alert_time is None or \
                        current_time - last_alert_time >= timedelta(hours=1):
                    print(f"Failure threshold ({FAILURE_THRESHOLD}) exceeded! Sending alert...")
                    send_alert_email(failures)
                    # updates the variable after the email was sent
                    last_alert_time = current_time
                else:
                    print("Threshold exceeded but alert was recently sent. Waiting...")

            # The code will be executed every CHECK_INTERVAL time, in our case 10 seconds
            time.sleep(CHECK_INTERVAL)

        # shows that message if the script is finished by a user via CTRL + C
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            break
        # handles all the errors
        except Exception as e:
            print(f"Unexpected error: {e}")

# calls the final function
main()
