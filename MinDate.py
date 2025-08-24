# Importing necessary libraries.
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector

# MySQL Connection
mydb = mysql.connector.connect(
    charset="utf8",
    user='user',
    password='password',
    database='cvedb',
    host='127.0.0.1'
)
cursor = mydb.cursor()

# List to for
cve_distro = ["almalinux", "debian", "redhat", "rockylinux", "ubuntu", "ubuntupro"]

for distro in cve_distro:
    cursor.execute(f"SELECT cve from cvedb5.{distro}")
    records = cursor.fetchall()
    for cve in records:
        if cve[0] is None:
            pass
        else:
            # Removing invalid character from cve
            temp = str(cve)
            temp = str((temp.replace("('", "")))
            temp = str((temp.replace("',)", "")))
            # Avoid duplicated information
            select1 = f"SELECT CVE from cvemindate WHERE (CVE = '{temp}')"
            cursor.execute(select1)
            records1 = cursor.fetchall()
            if records1 == []:
                # Select CVE from all Linux
                select_alma = f"SELECT least(Published, Published_NIST) from cvedb5.almalinux a WHERE (CVE = '{temp}')"
                select_debian = f"SELECT Published_NIST from cvedb5.debian d WHERE (CVE = '{temp}')"
                select_redhat = f"SELECT least(Published, Published_NIST) from cvedb5.redhat a WHERE (CVE = '{temp}')"
                select_rocky = f"SELECT least(Published, Published_NIST) from cvedb5.rockylinux a WHERE (CVE = '{temp}')"
                select_ubuntu = f"SELECT least(Published, Published_NIST) from cvedb5.ubuntu a WHERE (CVE = '{temp}')"
                select_ubuntupro = f"SELECT least(Published, Published_NIST) from cvedb5.ubuntu_PRO a WHERE (CVE = '{temp}')"
                # Put all dates in a list
                listcve = [select_alma, select_debian, select_redhat, select_rocky, select_ubuntu, select_ubuntupro]
                mindate = []
                for x in listcve:
                    cursor.execute(x)
                    records = cursor.fetchall()
                    for z in records:
                        if z[0] is None or z[0] == [] or z[0] == '':
                            tt = 0
                        else:
                            mindate.append(z[0])
                if not mindate:
                    print("Your list is empty")
                    print(temp)
                else:
                    date2 = min(mindate)
                    ## Write to DataBase
                    sql = "INSERT INTO cvemindate (CVE, MinDate) VALUES (%s, %s)"
                    values = (temp, date2)
                    cursor.execute(sql, values)
                    mydb.commit()
            else:
                #print('CVE already exists')
                pass

print("Finished")

# Make sure connection is closed
cursor.close()
mydb.close()
