# Importing necessary libraries.
import nvdlib
import re
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb5', host='127.0.0.1')
cursor = mydb.cursor()

"""
############### Instructions ###############

Before you begin, request your NIST key - https://nvd.nist.gov/developers/request-an-api-key

And change key variable
"""

# Starting
print(f'"Welcome to collector of CVEs from NIST/NVD´s Database."')
year = ["2019", "2020", "2021", "2022", "2023"]
key = "xxx-xxx-xxx"

# Loop search for 5 years
for y in year:
    # Variables for searching on NIST - Divided into multiple searches to avoid timeouts
    r1 = f"nvdlib.searchCVE(pubStartDate = '{y}-01-01 00:00', pubEndDate = '{y}-02-01 23:59', key='{key}')"
    r2 = f"nvdlib.searchCVE(pubStartDate = '{y}-02-02 00:00', pubEndDate = '{y}-03-01 23:59', key='{key}')"
    r3 = f"nvdlib.searchCVE(pubStartDate = '{y}-03-02 00:00', pubEndDate = '{y}-04-01 23:59', key='{key}')"
    r4 = f"nvdlib.searchCVE(pubStartDate = '{y}-04-02 00:00', pubEndDate = '{y}-05-01 23:59', key='{key}')"
    r5 = f"nvdlib.searchCVE(pubStartDate = '{y}-05-02 00:00', pubEndDate = '{y}-06-01 23:59', key='{key}')"
    r6 = f"nvdlib.searchCVE(pubStartDate = '{y}-06-02 00:00', pubEndDate = '{y}-07-01 23:59', key='{key}')"
    r7 = f"nvdlib.searchCVE(pubStartDate = '{y}-07-02 00:00', pubEndDate = '{y}-08-01 23:59', key='{key}')"
    r8 = f"nvdlib.searchCVE(pubStartDate = '{y}-08-02 00:00', pubEndDate = '{y}-09-01 23:59', key='{key}')"
    r9 = f"nvdlib.searchCVE(pubStartDate = '{y}-09-02 00:00', pubEndDate = '{y}-10-01 23:59', key='{key}')"
    r10 = f"nvdlib.searchCVE(pubStartDate = '{y}-10-02 00:00', pubEndDate = '{y}-11-01 23:59', key='{key}')"
    r11 = f"nvdlib.searchCVE(pubStartDate = '{y}-11-02 00:00', pubEndDate = '{y}-12-01 23:59', key='{key}')"
    r12 = f"nvdlib.searchCVE(pubStartDate = '{y}-12-02 00:00', pubEndDate = '{y}-12-31 23:59', key='{key}')"

    # Loop search for CVEs on NVD Base and write to a MYSQL´s Database
    # Loop for looking for each CVE
    for var in (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12):
        search = eval(var)
        for eachCVE in search:
            # String convert
            nistid = str(eachCVE.id)
            # package = str(eachCVE.configurations)
            severity = str(eachCVE.score)
            # Filter to get severity - LOW, MEDIUM, HIGH, CRITICAL and others
            severity = str((re.findall('[A-Z]{2,}', severity)))
            # Removing [´ and ´] from severity
            severity = str((severity.replace("['", "")))
            severity = str((severity.replace("']", "")))
            # Get Date
            date_published = str(eachCVE.published)
            date_published = str((re.findall('[0-9]{4}-[0-9]{2}-[0-9]{2}', date_published)))
            # Removing [´ and ´] from date
            date_published = str((date_published.replace("['", "")))
            date_published = str((date_published.replace("']", "")))
            # Write to DataBase
            sql = "INSERT INTO nist (CVE, Published, Severity) VALUES (%s, %s, %s)"
            values = (nistid, date_published, severity)
            cursor.execute(sql, values)
            mydb.commit()

print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()

