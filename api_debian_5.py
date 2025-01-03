# Importing necessary libraries.
import urllib.request
import time
import requests
import pathlib
import urllib
import json
from datefinder import find_dates
import pandas as pd
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Get Debian´s CVEs and store the response of URL
url = str('https://security-tracker.debian.org/tracker/data/json')
response = urllib.request.urlopen(url)

# Load JSON´s information
json_debian = json.loads(response.read())
for information in json_debian:
    package = str(information)
    for a in json_debian[package]:
        idcve = str(a)
        # Avoid duplicated information
        select = f"SELECT CVE from debian WHERE CVE = '{idcve}'"
        cursor.execute(select)
        records = cursor.fetchall()
        debian_temp_file = None
        if records == []:
            # Verify if NIST has the CVE and catch date and severity
            select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{idcve}'"
            cursor.execute(select)
            records = cursor.fetchall()
            for x in records:
                nist_date = x[1]
                nist_severity = x[2]
                for b in json_debian[package][idcve]["releases"]:
                    distro = str(b)
                    print(distro)
                    print(idcve)
                    debian_temp_file = None
                    status = str((json_debian[package][idcve]["releases"][distro]["status"]))
                    # Look for resolved date, version and severity
                    if status == "resolved":
                        priority = str((json_debian[package][idcve]["releases"][distro]["urgency"]))
                        if distro == "buster":
                            try:
                                version_resolve = str((json_debian[package][idcve]["releases"][distro]["repositories"]["buster-security"]))
                            except KeyError:
                                version_resolve = "Check Manually"
                        else:
                            version_resolve = str((json_debian[package][idcve]["releases"][distro]["repositories"][distro]))
                        # Get correction date from releases packages - changelog
                        ## Mount and open URL
                        ### Get first letter
                        letter = package[0]
                        # wait to avoid timeouts
                        time.sleep(3)
                        debian_url = f"https://metadata.ftp-master.debian.org/changelogs/main/{letter}/{package}/{package}_{version_resolve}_changelog"
                        print(debian_url)
                        # Save Temporary File - changelog
                        debian_temp_file = requests.get(debian_url)
                        print(debian_temp_file)
                        if debian_temp_file.status_code != 404:
                            pathlib.Path('changelog').write_bytes(debian_temp_file.content)
                            # Open temporary file - changelog
                            filetemp = open('changelog', encoding="UTF8")
                            # Find package version on changelog
                            try:
                                for line_number, line in enumerate(filetemp):
                                    string_package = str(f"{package} ({version_resolve}) ")
                                    # Find date - First occurrence
                                    if line.startswith(string_package):
                                        for line_number, line in enumerate(filetemp):
                                            string_date = " -- "
                                            if line.startswith(string_date):
                                                temp_date = line
                                                temp_date = find_dates(temp_date)
                                                for match in temp_date:
                                                    date = f"{match.year}/{match.month}/{match.day}"
                                                    resolved_date = pd.to_datetime(date, errors='coerce')
                                                break
                            except KeyError:
                                resolved_date = "Check Manually"
                            # Close temp file
                            filetemp.close()
                        else:
                            resolved_date = "Check Manually"

                        # Write to DataBase
                        sql = "INSERT INTO debian (CVE, Published_NIST, Severity_NIST, Priority, Package, Distro, Status, Version_Resolved, Resolved) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                        values = (idcve, nist_date, nist_severity, priority, package, distro, status, version_resolve, resolved_date)
                        cursor.execute(sql, values)
                        mydb.commit()


                    else:
                        version_resolve = str((json_debian[package][idcve]["releases"][distro]["repositories"][distro]))
                        priority = str((json_debian[package][idcve]["releases"][distro]["urgency"]))
                        # Write to DataBase
                        sql = "INSERT INTO debian (CVE, Published_NIST, Severity_NIST, Priority, Package, Distro, Status) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                        values = (idcve, nist_date, nist_severity, priority, package, distro, status)
                        cursor.execute(sql, values)
                        mydb.commit()

# Close URL
response.close()

print("Finished")
