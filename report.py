# Importing necessary libraries.

### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb5', host='127.0.0.1')
cursor = mydb.cursor()

# Get Unique CVEs by NIST and Linux distributions and sum
print("")
print("**************************************************************")
print("Get Unique CVEs by NIST and Linux distributions and sum")
print("**************************************************************")
print("")
#
distro = ["nist", "almalinux", "debian", "redhat", "rockylinux", "ubuntu"]
for a in range(len(distro)):
    temp = (distro[a])
    sql = f"SELECT COUNT(DISTINCT CVE) FROM {temp}"
    cursor.execute(sql)
    total = str(cursor.fetchall())
    total = str((total.replace("[(", "")))
    total = str((total.replace(",)]", "")))
    total = int(total)
    print(f"Distribution {temp} has {total} CVEs")


# Get Severity CVEs from NIST and Linux distributions and sum
print("")
print("**************************************************************")
print("Get Total Severity CVEs from NIST and Linux distributions")
print("**************************************************************")
print("")
distro = ["almalinux", "debian", "redhat", "rockylinux", "ubuntu"]
for a in range(len(distro)):
   temp = str((distro[a]))
   if temp == 'ubuntu' or temp == 'debian':
       severity_column = 'Priority'
   else:
       severity_column = 'Severity'
   # Get Records and Sum - Severity Distro and NIST
   list_severities_distro = f"SELECT DISTINCT ({severity_column}) FROM {temp}"
   cursor.execute(list_severities_distro)
   records = cursor.fetchall()
   for x in records:
       priority = str(x)
       priority = str((priority.replace("('", "")))
       priority = str((priority.replace("',)", "")))
       severity_distro = f"SELECT COUNT(DISTINCT(CVE)) from {temp} where {severity_column} = '{priority}'"
       cursor.execute(severity_distro)
       total = str(cursor.fetchall())
       total = str((total.replace("[(", "")))
       total = str((total.replace(",)]", "")))
       total = int(total)
       print(f"Distribution {temp} has {total} {priority} vulnerabilities")

   print("")
   print("")
   list_severities_nist = f"SELECT DISTINCT (Severity_NIST) FROM {temp}"
   cursor.execute(list_severities_nist)
   records = cursor.fetchall()
   for x in records:
       priority = str(x)
       priority = str((priority.replace("('", "")))
       priority = str((priority.replace("',)", "")))
       severity_nist = f"SELECT COUNT(DISTINCT(CVE)) from {temp} where Severity_NIST = '{priority}'"
       cursor.execute(severity_nist)
       total = str(cursor.fetchall())
       total = str((total.replace("[(", "")))
       total = str((total.replace(",)]", "")))
       total = int(total)
       print(f"Distribution {temp} has {total} {priority} NIST vulnerabilities")
   print("")
   print("")

   
