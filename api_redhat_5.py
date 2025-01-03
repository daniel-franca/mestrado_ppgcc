"""
Script to search RedHat CVEs and Vulnerabilities.
Based on: https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index#example_script
"""

#!/usr/bin/env python

# Importing necessary libraries.
import sys
import requests
from datetime import datetime, timedelta
import pathlib
import json
import pandas as pd
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Script Red Hat
API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'


def get_data(query):

    full_query = API_HOST + query
    r = requests.get(full_query)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, full_query))
        sys.exit(1)

    if not r.json():
        print('No data returned with the following query:')
        print(full_query)
        sys.exit(0)

    return r.json()

# Get a list all issues from 2023
endpoint = '/cve.json'
params = str("after=2017-12-31&per_page=100000000")
data = get_data(endpoint + '?' + params)

for cve in data:
    idcve = str(cve['CVE'])
    severity = str(cve['severity'])
    date = str(pd.to_datetime(cve['public_date']).date())
    url = str(cve['resource_url'])
    try:
        # Looking for Corrections Status
        # Save Temporary File
        json_url = requests.get(url)
        pathlib.Path('temp.json').write_bytes(json_url.content)
        # Open temporary file
        filetemp = open('temp.json', encoding="UTF8")
        # Load JSON  s information and temporary lists
        json_load = json.load(filetemp)
        # Loop for write each resolved CVE on CVS file
        # Searching for Red Hat Enterprise Linux x Version
        for information in json_load["package_state"]:
            if "Red Hat Enterprise Linux" in information["product_name"]:
                product_name = str(information["product_name"])
                fix_state = str(information["fix_state"])
                fix_state = fix_state.lower()
                if fix_state == "resolved":
                    release_date = str(pd.to_datetime(information["release_date"]).date())
                    # Verify if NIST has the CVE and catch date and severity
                    select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{idcve}'"
                    cursor.execute(select)
                    records = cursor.fetchall()
                    for x in records:
                        nist_date = x[1]
                        nist_severity = x[2]
                        # Write to DataBase
                        sql = "INSERT INTO redhat (CVE, Version, Published, Published_NIST, Resolved, Severity, Severity_NIST) VALUES (%s, %s, %s, %s, %s, >                        values = (idcve, product_name, date, nist_date, release_date, severity, nist_severity)
                        cursor.execute(sql, values)
                        mydb.commit()
                else:
                    # Verify if NIST has the CVE and catch date and severity
                    select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{idcve}'"
                    cursor.execute(select)
                    records = cursor.fetchall()
                    for x in records:
                        nist_date = x[1]
                        nist_severity = x[2]
                        # Write to DataBase
                        sql = "INSERT INTO redhat (CVE, Version, Published, Published_NIST, FixState, Severity, Severity_NIST) VALUES (%s, %s, %s, %s, %s, >                        values = (idcve, product_name, date, nist_date, fix_state, severity, nist_severity)
                        cursor.execute(sql, values)
                        mydb.commit()
    except KeyError:
        pass

print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()