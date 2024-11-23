# Importing necessary libraries.
from datetime import datetime
import time
import re
import json
import urllib.request
from urllib.request import urlopen
import pandas as pd
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Set page number
pagenumber = 6700

# Searching through URLs
while pagenumber <= 25000:
    # URL to get Ubuntu´s CVEs
    baseurl = 'https://ubuntu.com/security/cves.json?limit=100&offset='
    # Set Complete URL
    page = str(pagenumber)
    url = str((baseurl + page))
    print(url)
    # Looking for Corrections Status
    # store the response of URL
    req = urllib.request.Request(url)
    req.add_header('User-Agent',
                   '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"')
    try:
        response = urllib.request.urlopen(req, timeout=120)
    except HTTPError:
        time.sleep(120)
        response = urllib.request.urlopen(req, timeout=120) 
    # Load JSON´s information
    json_ubuntu = json.loads(response.read())
    for information in json_ubuntu['cves']:
        idcve = str(information['id'])
        print(idcve)
        for information in json_ubuntu['cves']:
            idcve = str(information['id'])
            # Avoid duplicated information
            select = f"SELECT CVE from ubuntu WHERE CVE = '{idcve}'"
            cursor.execute(select)
            records = cursor.fetchall()
            if records == []:
                published = str(pd.to_datetime(information["published"]).date())
                priority = str(information['priority'])
                for a in range(len(information['packages'])):
                    package = str(information['packages'][a]['name'])
                    for b in range(len(information['packages'][a]['statuses'])):
                        distro = str(information['packages'][a]['statuses'][b]['release_codename'])
                        support = str(information['packages'][a]['statuses'][b]['description'])
                        status = str(information['packages'][a]['statuses'][b]['status'])
                        # Ignoring status "Does not exist" - DNE | needs-triage | ignored | not-affected
                        if status != 'DNE' and status != 'needs-triage' and status != 'ignored' and status != 'not-affected':
                            # Verify if NIST has the CVE and catch date and severity
                            select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{idcve}'"
                            cursor.execute(select)
                            records = cursor.fetchall()
                            for x in records:
                                nist_date = x[1]
                                nist_severity = x[2]
                                # Get correction date from releases packages
                                if ((status == 'released') and (distro != 'upstream')):
                                    try:
                                        # Mount and open URL
                                        ubuntu_url = f"https://launchpad.net/ubuntu/+source/{package}/{support}"
                                        ubuntu_package_page = urlopen(ubuntu_url)
                                        # Wait to avoid blocks
                                        time.sleep(30)
                                        # Extract HTML information
                                        html_bytes = ubuntu_package_page.read()
                                        html = str(html_bytes.decode("utf-8"))
                                        # find changes URL
                                        change_url = str(re.findall(".*_source.changes", html))
                                        # Extract URL
                                        change_url = str((change_url.replace("['     <a href=", "")))
                                        change_url = str((change_url.replace('"', "")))
                                        change_url = str((change_url.replace("']", "")))                                    # Open Source Change URL
                                        source_change_url = change_url
                                        package_change_page = urlopen(source_change_url)
                                        # Extract HTML information
                                        html_bytes = package_change_page.read()
                                        html = str(html_bytes.decode("utf-8"))
                                        # find changes URL
                                        package_change_url = str(re.findall("Date: .*", html))
                                        # Extract Date
                                        # Replace characters
                                        resolved_date = str(package_change_url.replace("['Date: ", ""))
                                        resolved_date = str(resolved_date.replace("']", ""))
                                        resolved_date = str(resolved_date[5:16])
                                        date_format = '%d %b %Y'
                                        date_obj = str(datetime.strptime(resolved_date, date_format))
                                        resolved_date = datetime.strptime(date_obj, "%Y-%m-%d %H:%M:%S")
                                        resolved_date = str(resolved_date.strftime('%Y-%m-%d'))
                                    except:
                                        resolved_date = str("CHECK MANUALLY")
                                    # Write to DataBase
                                    sql = "INSERT INTO ubuntu (CVE, Published, Published_NIST, Priority, Severity_NIST, Package, Distro, Support, Status, Resolved) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                                    values = (idcve, published, nist_date, priority, nist_severity, package, distro, support, status, resolved_date)
                                    cursor.execute(sql, values)
                                    mydb.commit()
                                else:
                                    # Write to DataBase
                                    sql = "INSERT INTO ubuntu (CVE, Published, Published_NIST, Priority, Severity_NIST, Package, Distro, Support, Status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                                    values = (idcve, published, nist_date, priority, nist_severity, package, distro, support, status)
                                    cursor.execute(sql, values)
                                    mydb.commit()

    # Increment URL offset
    pagenumber += 1
    # Reset json_ubuntu and response variables
    json_ubuntu = None
    # Close URL
    response.close()
    response = None

print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()
