# Importing necessary libraries.
from datetime import datetime
import time
import re
import json
import urllib.request
from urllib.request import urlopen
import pandas as pd
from retrying import retry
import os
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Download json files to local drive
# Set page number
pagenumber = 0

# Searching through URLs
while pagenumber <= 26000:
    # URL to get Ubuntu´s CVEs
    baseurl = 'https://ubuntu.com/security/cves.json?limit=20&offset='
    # Set Complete URL
    page = str(pagenumber)
    url = str((baseurl + page))
    print(url)

    # Looking for Corrections Status
    # store the response of URL
    @retry
    def download(url):
        time.sleep(60)
        response = urllib.request.urlopen(url)
        # Load JSON´s information
        json_ubuntu = json.loads(response.read())
        # Save File
        with open(f'{pagenumber}.json', 'w') as file:
            json.dump(json_ubuntu, file)
            response.close()
            response = None
            # Reset json_ubuntu and responde variables
            json_ubuntu = None
    # Execute function download
    download(url)
    # Increment URL offset
    pagenumber += 1
print("Finished")

# Reading local json files
with os.scandir('/JSONS_FILE_DIR') as localfiles:
    # Load JSONs information
    for x in localfiles:
        if ".json" in x.name:
            with open(x, "r", encoding="utf-8") as jsonfile:
                json_ubuntu = json.load(jsonfile)
                # Looking for Corrections Status
                for information in json_ubuntu['cves']:
                    idcve = str(information['id'])
                    print(idcve)
                    # Avoid duplicated information
                    select = f"SELECT CVE from ubuntu WHERE CVE = '{idcve}'"
                    cursor.execute(select)
                    records = cursor.fetchall()
                    if not records:
                        published = str(pd.to_datetime(information["published"]).date())
                        priority = str(information['priority'])
                        for a in range(len(information['packages'])):
                            package = str(information['packages'][a]['name'])
                            for b in range(len(information['packages'][a]['statuses'])):
                                distro = str(information['packages'][a]['statuses'][b]['release_codename'])
                                support = str(information['packages'][a]['statuses'][b]['description'])
                                status = str(information['packages'][a]['statuses'][b]['status'])
                                # Verify if NIST has the CVE and catch date and severity
                                select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{idcve}'"
                                cursor.execute(select)
                                records = cursor.fetchall()
                                for x in records:
                                    nist_date = x[1]
                                    nist_severity = x[2]
                                    # Get correction date from releases packages
                                    if ((status == 'released') and (distro != 'upstream')):
                                        # Mount and open URL
                                        ubuntu_url = f"https://launchpad.net/ubuntu/+source/{package}/{support}"
                                        @retry
                                        def download2(ubuntu_url):
                                            try:
                                                ubuntu_package_page = urllib.request.urlopen(ubuntu_url)
                                                html_bytes = ubuntu_package_page.read()
                                                html = str(html_bytes.decode("utf-8"))
                                                return html
                                            except urllib.error.HTTPError as err:
                                                if err.code == 404:
                                                    html = None
                                                    return html
                                                else:
                                                    html_bytes = ubuntu_package_page.read()
                                                    html = str(html_bytes.decode("utf-8"))
                                                    return html
                                        # Execute function download2
                                        html2 = download2(ubuntu_url)
                                        try:
                                            # find changes URL
                                            change_url = str(re.findall(".*_source.changes", html2))
                                            # Extract URL
                                            change_url = str((change_url.replace("['     <a href=", "")))
                                            change_url = str((change_url.replace('"', "")))
                                            change_url = str((change_url.replace("']", "")))
                                            # Open Source Change URL
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
                                            # Reset variables
                                            html_bytes = None
                                        except:
                                            resolved_date = str("CHECK MANUALLY")

                                        # Write to DataBase
                                        sql = "INSERT INTO ubuntu (CVE, Published, Published_NIST, Priority, Severity_NIST, Package, Distro, Support, Status, Resolved) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                                        values = (
                                        idcve, published, nist_date, priority, nist_severity, package, distro,
                                        support, status, resolved_date)
                                        cursor.execute(sql, values)
                                        mydb.commit()
                                    else:
                                        # Write to DataBase
                                        sql = "INSERT INTO ubuntu (CVE, Published, Published_NIST, Priority, Severity_NIST, Package, Distro, Support, Status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                                        values = (idcve, published, nist_date, priority, nist_severity, package, distro, support, status)
                                        cursor.execute(sql, values)
                                        mydb.commit()
                                        # Reset json_ubuntu
            json_ubuntu = None

print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()
