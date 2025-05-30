# Importing necessary libraries.
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector
import re

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

# Tables to check
DEBTable = ["debian", "ubuntu", "ubuntu_PRO"]
RPMTable = ["redhat", "almalinux", "rockylinux"]
distros  = list(set(DEBTable).union(RPMTable))

# Create list of CVEs
deb_cves = set()
rpm_cves = set()

# Check CVEs from Ubuntu and Debian
for distro in DEBTable:
    cursor.execute(f"SELECT DISTINCT cve from cvedb5.{distro}")
    deb_cves.update(result[0] for result in cursor.fetchall())

# Check CVEs from RedHat, Alma and Rocky Linux
for distro in RPMTable:
    cursor.execute(f"SELECT DISTINCT cve from cvedb5.{distro}")
    rpm_cves.update(result[0] for result in cursor.fetchall())

# Check CVEs present in both families (DEB and RPM)
comumcves = deb_cves & rpm_cves

# Get Package´s Name
# Create list of Packages
package_cves = set()

for cve in comumcves:
    for linux in distros:
        cursor.execute(f"SELECT Package from cvedb5.{linux} where CVE='{cve}'")
        package_cves.update(result[0] for result in cursor.fetchall())

# Regex to stract package´s name
pattern = r'^([a-zA-Z0-9_+\-]+?)(?=[:-]\d)'

packages_list = []

for package in package_cves:
    file = package
    match = re.match(pattern, file)
    if match:
        packages_list.append(match.group(1))
    else:
        # Fallback
        packages_list.append(file.split('-')[0])

# Write to DataBase
for package in packages_list:
    sql = "INSERT INTO packages (Package) VALUES (%s)"
    cursor.execute(sql, [package])
    mydb.commit()

print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()
