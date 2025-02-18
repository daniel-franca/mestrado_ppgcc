# Importing necessary libraries.

import datetime
from pydoc import resolve

import pandas as pd

### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='user', password='password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Calculate resolved days
def main(distro, version, sql):
    cursor.execute(sql)
    records = cursor.fetchall()
    for x in records:
        cve=(str(x[0]))
        if x[3] != "Not affected" or x[3] != "not-affected" or x[3] != "DNE":
            # If not resolved or Check Manually, date = 01/Jan/2024
            if not x[1] or x[1] == "[]" or "CHECK" in x[1]:
                date = datetime.datetime(2024, 1, 1)
                resolved = date.date()
                # Get CVE´s Year from NIST
                year = str(x[2])
                # Remove extra characters
                year = str((year.replace("[('", "")))
                year = str((year.replace("',)]", "")))
                # Convert to date format
                date_format = '%Y-%m-%d'
                year = datetime.datetime.strptime(year, date_format).date().year
            else:
                resolved = x[1]
                if distro == 'debian':
                    date_format = '%Y-%m-%d %H:%M:%S'
                    resolved = datetime.datetime.strptime(resolved, date_format).date()
                    # Get CVE´s Year from NIST
                    year = str(x[2])
                    # Remove extra characters
                    year = str((year.replace("[('", "")))
                    year = str((year.replace("',)]", "")))
                    # Convert to date format
                    date_format = '%Y-%m-%d'
                    year = datetime.datetime.strptime(year, date_format).date().year
                else:
                    date_format = '%Y-%m-%d'
                    resolved = datetime.datetime.strptime(resolved, date_format).date()
                    # Get CVE´s Year from NIST
                    year = str(x[2])
                    # Remove extra characters
                    year = str((year.replace("[('", "")))
                    year = str((year.replace("',)]", "")))
                    # Convert to date format
                    date_format = '%Y-%m-%d'
                    year = datetime.datetime.strptime(year, date_format).date().year
            # Get MinDate from CVE
            sql2 = f"select MinDate from cvemindate where cve ='{cve}'"
            cursor.execute(sql2)
            # Remove extra characters
            records = str(cursor.fetchall())
            records = str((records.replace("[(datetime.date(", "")))
            records = str((records.replace(", ", "-")))
            records = str((records.replace("),)]", "")))
            records = str((records.replace(", ), (", "")))
            # Convert to date format
            date_format = '%Y-%m-%d'
            mindate = datetime.datetime.strptime(records, date_format).date()
            # Calculate resolved days
            days = resolved - mindate
            days = days.days
            # Write to DB
            sql = "INSERT INTO results (CVE, Year, Distro, Version, MinDate, Resolved, Days) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            values = (cve, year, distro, version, mindate, resolved, days)
            cursor.execute(sql, values)
            mydb.commit()

# Define Linux Distribution
distro = ["rockylinux", "almalinux", "ubuntu", "redhat", "debian"]

# Specific parameters
for a in distro:
    if a == "debian":
        version = ["buster", "bullseye", "bookworm", "sid", "trixie"]
        for b in version:
            sql = f"SELECT CVE, Resolved, Published_NIST, Status FROM {a} where Distro IN ('{b}')"
            main(a, b, sql)
    else:
        if a == "redhat":
            version = ["6", "7", "8", "9"]
            for b in version:
                sql = f"SELECT DISTINCT (CVE), Resolved, Published_NIST, FixState FROM {a} where Version IN ('Red Hat Enterprise Linux {b}')"
                main(a, b, sql)
        else:
            if a == "ubuntu":
                version = ["xenial", "bionic", "focal", "jammy"]
                for b in version:
                    sql = f"SELECT CVE, Resolved, Published_NIST, Status FROM {a} where Distro IN ('{b}')"
                    main(a, b, sql)
            else:
                if a == "almalinux":
                    version = ["8", "9"]
                    for b in version:
                        sql = f"SELECT CVE, Resolved, Published_NIST, Severity FROM {a} where Version IN ('AlmaLinux {b}')"
                        main(a, b, sql)
                else:
                    if a == "rockylinux":
                        version = ["8", "9"]
                        for b in version:
                            sql = f"SELECT CVE, Resolved, Published_NIST, Severity FROM {a} where Version IN ('Rocky Linux {b}')"
                            main(a, b, sql)

print("Finished")

# Make sure DB´s connection is closed
cursor.close()
mydb.close()
