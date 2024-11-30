# Importing necessary libraries.
import mysql.connector
import requests
import socket
from fake_useragent import UserAgent
from datetime import datetime
import time
import re
import json
import urllib.request
from urllib.request import urlopen
from urllib.error import HTTPError
import pandas as pd
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Instantiate the UserAgent class
ua = UserAgent()

# Lista de endereços IPv6 a serem utilizados
ips = ['::1', 'Another IPv6']

# Change IPs
def get_json_data(url, ip):
    # socket source IP
    s = None
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind((ip, 0))  # Escolhe uma porta aleatória

    # Get random user agents
    random_ua = ua.random

    # Pass the random user agents to the user-agent headers
    request_headers = {
        'user-agent': random_ua
    }

    # Connections with socket json
    s.connect(('ubuntu.com', 443))  # Conectar ao site (HTTPS)
    response = requests.get(url, headers= request_headers)
    response.raise_for_status()
    return response.json()

# Change IPs
def get_site_data(url, ip):
    # socket source IP
    s = None
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind((ip, 0))  # Escolhe uma porta aleatória

    # Get random user agents
    random_ua = ua.random

    # Pass the random user agents to the user-agent headers
    request_headers = {
        'user-agent': random_ua
    }

    # Connections with socket json
    s.connect(('launchpad.net', 443))  # Conectar ao site (HTTPS)
    response = (requests.get(url, headers= request_headers)).content
    return response

# Loop para obter os dados para cada offset
for i in range(25000):
    for ip in ips:
        url = f"https://ubuntu.com/security/cves.json?limit=100&offset={i}"
        print(url)
        try:
            data = get_json_data(url, ip)
            for information in data['cves']:
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
                            #select = f"SELECT CVE, Published, Severity from nist WHERE CVE LIKE '{idcve}'"
                            #cursor.execute(select)
                            #records = cursor.fetchall()
                            #for x in records:
                            #    nist_date = x[1]
                            #    nist_severity = x[2]
                            # Get correction date from releases packages
                            if status == 'released' and status != 'upstream':
                                try:
                                    # Mount and open URL
                                    ubuntu_url = f"https://launchpad.net/ubuntu/+source/{package}/{support}"
                                    ubuntu_package_page = get_site_data(ubuntu_url, ip)
                                    # Extract HTML information
                                    html_bytes = ubuntu_package_page
                                    html = str(html_bytes.decode("utf-8"))
                                    # find changes URL
                                    change_url = str(re.findall(".*_source.changes", html))
                                    # Extract URL
                                    change_url = str((change_url.replace("['     <a href=", "")))
                                    change_url = str((change_url.replace('"', "")))
                                    change_url = str((change_url.replace("']", "")))  # Open Source Change URL
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
                                sql = "INSERT INTO ubuntu (CVE, Published, Priority, Package, Distro, Support, Status, Resolved) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                                values = (
                                idcve, published, priority, package, distro, support, status, resolved_date)
                                cursor.execute(sql, values)
                                mydb.commit()
                            else:
                                # Write to DataBase
                                sql = "INSERT INTO ubuntu (CVE, Published, Priority, Package, Distro, Support, Status) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                                values = (
                                idcve, published, priority, package, distro, support, status)
                                cursor.execute(sql, values)
                                mydb.commit()

        except requests.exceptions.RequestException as e:
            print(f"Erro ao obter dados para {url}: {e}")
print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()
