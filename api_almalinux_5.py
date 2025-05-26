# Importing necessary libraries.
from datetime import datetime
import pathlib
import requests
import json
import pandas as pd
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Base URL
base = 'https://errata.almalinux.org'

# Get a list all issues
# Almalinux 8
# Set URL
endpoint8 = '/8/errata.full.json'
url = str(base + endpoint8)

# Looking for Corrections Status
# Save Temporary File
json_url = requests.get(url)
pathlib.Path('temp.json').write_bytes(json_url.content)
# Open temporary file
filetemp = open('temp.json', encoding="UTF8")
# Load JSON´s information
json_load = json.load(filetemp)
for information in json_load['data']:
    # Get only security and bugfix types
    if information['type'] == "security":
        idalma = information['id']
        # get length of information minus 1 (lists start from 0)
        infolen = (len(information['references'])) -1
        n = 0
        while n <= infolen:
            if "CVE-" in information['references'][n]['id']:
                cve = str(information['references'][n]['id'])
            else:
                cve = "Check Manually"
            # Get information
            version = "AlmaLinux 8"
            package = str(information['packages'][0]['name'])
            published = information['issued_date']
            date = str(datetime.fromtimestamp(published))
            date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
            date = str(date.strftime('%Y-%m-%d'))
            resolved = information['updated_date']
            date_resolved = str(datetime.fromtimestamp(resolved))
            date_resolved = str(pd.to_datetime(date_resolved).date())
            severity = str(information['severity'])
            notice_type = str(information['type'])
            # Verify if NIST has the CVE and catch date and severity
            select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{cve}'"
            cursor.execute(select)
            records = cursor.fetchall()
            for x in records:
                nist_date = x[1]
                nist_severity = x[2]
                # Write to DB
                sql = "INSERT INTO almalinux (idalma, CVE, Version, Published, Published_NIST, Resolved, Severity, Severity_NIST, Package) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                values = (idalma, cve, version, date, nist_date, date_resolved, severity, nist_severity, package)
                cursor.execute(sql, values)
                mydb.commit()
            n += 1

# Almalinux 9
# Set URL
endpoint9 = '/9/errata.full.json'
url = str(base + endpoint9)

# Looking for Corrections Status
# Save Temporary File
json_url = requests.get(url)
pathlib.Path('temp.json').write_bytes(json_url.content)
# Open temporary file
filetemp = open('temp.json', encoding="UTF8")
# Load JSON´s information
json_load = json.load(filetemp)
for information in json_load['data']:
    # Get only security and bugfix types
    if information['type'] == "security":
        idalma = information['id']
        # get length of information minus 1 (lists start from 0)
        infolen = (len(information['references'])) - 1
        n = 0
        while n <= infolen:
            if "CVE-" in information['references'][n]['id']:
                cve = str(information['references'][n]['id'])
            else:
                cve = "Check Manually"
            # Get information
            version = "AlmaLinux 9"
            package = str(information['packages'][0]['name'])
            published = information['issued_date']
            date = str(datetime.fromtimestamp(published))
            date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
            date = str(date.strftime('%Y-%m-%d'))
            resolved = information['updated_date']
            date_resolved = str(datetime.fromtimestamp(resolved))
            date_resolved = str(pd.to_datetime(date_resolved).date())
            severity = str(information['severity'])
            notice_type = str(information['type'])
            # Verify if NIST has the CVE and catch date and severity
            select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{cve}'"
            cursor.execute(select)
            records = cursor.fetchall()
            for x in records:
                nist_date = x[1]
                nist_severity = x[2]
                # Write to DB
                sql = "INSERT INTO almalinux (idalma, CVE, Version, Published, Published_NIST, Resolved, Severity, Severity_NIST, Package) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                values = (idalma, cve, version, date, nist_date, date_resolved, severity, nist_severity, package)
                cursor.execute(sql, values)
                mydb.commit()
            n += 1

# Printing end of execution
print("Finished")

# Make sure DB´s connection is closed
cursor.close()
mydb.close()

