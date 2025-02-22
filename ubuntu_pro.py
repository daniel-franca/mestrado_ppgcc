### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector
import csv
import os

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='user', password='password', database='cvedb', host='127.0.0.1')
cursor = mydb.cursor()

with os.scandir('/JSONS_FILE_DIR') as localfiles:
    # Open CSV File
    for x in localfiles:
        with open(x, newline='') as csvfile:
            ubuntu = csv.reader(csvfile, delimiter=',', quotechar='|')
            for row in ubuntu:
                cve = row[0]
                distro  =row[1]
                package = row[2]
                version = row[3]
                resolved = row[4]
                if resolved != "None":
                    sql = f'UPDATE ubuntupro SET Resolved = "{resolved}" WHERE CVE LIKE "{cve}" AND Distro LIKE "{distro}" AND Support LIKE "{version}"'
                    cursor = mydb.cursor()
                    cursor.execute(sql)
                    mydb.commit()

print("Finished")

# Make sure DB´s connection is closed
cursor.close()
mydb.close()
