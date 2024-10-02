# Importing necessary libraries.
import pandas as pd
import pathlib
import requests
import json
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Set page number
pagenumber = 0

# Searching through URLs
while pagenumber < 300:
    # Set Bse URL
    baseurl = str('https://apollo.build.resf.org/v2/advisories?page=')
    page = str(pagenumber)
    url = str((baseurl + page))
    # Save Temporary File
    json_url = requests.get(url)
    pathlib.Path('temp.json').write_bytes(json_url.content)
    # Open temporary file
    filetemp = open('temp.json', encoding="UTF8")
    # Load JSON´s information and temporary lists
    json_load = json.load(filetemp)
    # Searching CVEs
    for information in json_load['advisories']:
        # Select only security case
        if "SECURITY" in information['type']:
            # Iterate all versions and collect data
            for a in range(len(information['affectedProducts'])):
                idrocky = str(information['name'])
                version = str(information['affectedProducts'])
                version = str((version.replace("['", "")))
                version = str((version.replace("']", "")))
                publishedAt = str(information['publishedAt'])
                date_resolved = str(pd.to_datetime(publishedAt).date())
                severity = str(information['severity'])
                severity = str((severity.replace("SEVERITY_", "")))
                # Iterate all CVEs
                for b in range(len(information['cves'])):
                    cve = str(information['cves'][b]['name'])
                    # Finding date from RedHat´s table
                    select_date_redhat = f"SELECT Published from redhat WHERE CVE LIKE '{cve}' LIMIT 1"
                    cursor.execute(select_date_redhat)
                    records = cursor.fetchall()
                    date = str(records)
                    # Removing (' and ',) from date
                    date = str((date.replace("('", "")))
                    date = str((date.replace("',)", "")))
                    # Removing [ and ] from date
                    date = str((date.replace("[", "")))
                    date = str((date.replace("]", "")))
                    # Verify if NIST has the CVE and catch date and severity
                    select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{cve}'"
                    cursor.execute(select)
                    records = cursor.fetchall()
                    for x in records:
                        nist_date = x[1]
                        nist_severity = x[2]
                        # Write to DB
                        sql = "INSERT INTO rockylinux (idrocky, CVE, Version, Published, Published_NIST, Resolved, Severity, Severity_NIST) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                        values = (idrocky, cve, version, date, nist_date, date_resolved, severity, nist_severity)
                        cursor.execute(sql, values)
                        mydb.commit()
    # Next Page - URL
    pagenumber += 1

# Printing end of execution
print("Finished")

# Make sure DB´s connection is closed
cursor.close()
mydb.close()
