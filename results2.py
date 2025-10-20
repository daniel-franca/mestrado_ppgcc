# Importing necessary libraries.
### https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-transaction.html
import mysql.connector
import re
import datetime
import traceback
from collections import defaultdict
import sys

# MySQL Connection
mydb = mysql.connector.connect(charset="utf8", user='cvedb_user', password='change_password', database='cvedb5', host='127.0.0.1')
cursor = mydb.cursor()

def parse_date(date_string, format_list):
    if not isinstance(date_string, str):
        return date_string  # Já é uma data

    # Clean brackets and extra spaces
    date_string = re.sub(r'[\[\]]', '', date_string).strip()

    for fmt in format_list:
        try:
            return datetime.datetime.strptime(date_string, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"Date '{date_string}' doesn't match any formats: {format_list}")

# Calculate resolved days
def main(distro, version, sql):
    cursor.execute(sql)
    records = cursor.fetchall()

    for x in records:
        sys.stdout.write(f'\r{repr(x)}')
        cve = str(x[0])
        resolved = x[1]
        status = x[3] if len(x) > 3 else None  # Handle variable number of columns

        date_formats = [
            "%Y-%m-%dT%H:%M:%S",  # ISO format (with T)
            "%Y-%m-%d %H:%M:%S",  # Space separated
            "%Y-%m-%d",  # Date only
            "%d/%m/%Y",  # European format
            "%m/%d/%Y",  # US format
            "%Y-%m-%dT%H:%M:%S.%f"  # For fractional seconds
        ]

        # Process Published_NIST
        published_nist = x[2]
        year = None

        if published_nist:
            try:
                # Clean and parse published date
                published_str = re.sub(r'[\[\]()\']', '', str(published_nist)).strip()
                published_date = datetime.datetime.strptime(published_str, '%Y-%m-%d').date()
                year = published_date.year
            except (ValueError, TypeError):
                try:
                    # Try alternative parsing if first attempt fails
                    published_date = parse_date(published_str, date_formats)
                    year = published_date.year
                except (ValueError, TypeError):
                    print(f"Failed to parse published date: {published_nist}")
                    year = None

        # Process resolved date
        try:
            if resolved and any(keyword in str(resolved).lower()
                                for keyword in ['check manually', 'fix deferred', 'affected']):
                # Special cases
                resolved = datetime.date(2024, 1, 1)
            else:
                # Parse normally
                resolved = parse_date(resolved, date_formats)
        except (ValueError, TypeError):
            resolved = None

        # Skip if we don't have valid dates
        if resolved is None or year is None:
            continue

        # Get MinDate from CVE
        try:
            cursor.execute(f"SELECT MinDate FROM cvemindate WHERE cve = '{cve}'")
            result = cursor.fetchone()

            if result:
                mindate = result[0]  # Directly get the date object

                # Calculate resolved days
                days = (resolved - mindate).days

                # Write to DB
                sql_insert = """
                    INSERT IGNORE INTO results3 (CVE, Year, Distro, Version, MinDate, Resolved, Days)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                values = (cve, year, distro, version, mindate, resolved, days)
                cursor.execute(sql_insert, values)

        except Exception as e:
            print(f"Error processing CVE {cve}: {str(e)}")
    mydb.commit()
# Tables to check
DEBTable = ["debian", "ubuntu", "ubuntupro"]
RPMTable = ["redhat", "almalinux", "rockylinux"]
distros = list(set(DEBTable).union(RPMTable))

def norm_pkgname(package):
    package = re.sub(r'^(rhel|ubi)\d/', '', package)
    package = re.sub(r'-\d+:.*?\.el.*?$', '', package)
    package = re.sub(r':[^:]*$', '', package)
    #pattern = r'^([a-zA-Z0-9_+\-]+?)(?=[:-]\d)'
    #match = re.match(pattern, package)
    #if match:
    #    return match.group(1)
    return package

# Add field for normalized pkgname
try:
    for distro in distros:
        print(f"Adding field for {distro}")
        cursor.execute(f"ALTER TABLE cvedb5.{distro} ADD NormPackage VARCHAR(100)")
        cursor.execute(f"CREATE INDEX cvedb5_{distro}_Package ON cvedb5.{distro}(Package)")
        cursor.execute(f"CREATE INDEX cvedb5_{distro}_NormPackage ON cvedb5.{distro}(NormPackage)")
    mydb.commit()
except:
    traceback.print_exc()

for distro in distros:
    cursor.execute(f"SELECT Package from cvedb5.{distro}")
    pkgnames = set(result[0] for result in cursor.fetchall())
    print(f"{distro}: normalizing {len(pkgnames)} pkgnames")
    for pkgname in pkgnames:
        cursor.execute(f"UPDATE cvedb5.{distro} SET NormPackage=%s WHERE Package=%s", (norm_pkgname(pkgname), pkgname))
mydb.commit()

# Create list of CVEs
distro_cves = defaultdict(lambda: set())

for distro in distros:
    if distro == 'ubuntupro':
        continue  # Ubuntu Pro is a special case, it only has part of the packages
    cursor.execute(f"SELECT DISTINCT(cve) from cvedb5.{distro}")
    distro_cves[distro].update(result[0] for result in cursor.fetchall())

for distro, cves in distro_cves.items():
    print(distro, len(cves))

# Check CVEs present in all distros
comumcves = distro_cves['debian']
for distro, cves in distro_cves.items():
    comumcves &= cves
print('comumcves', len(comumcves))

cve_list = ','.join(f"'{cve}'" for cve in comumcves)

# Get Package´s Name
deb_pkgnames = set()
rpm_pkgnames = set()


for linux in DEBTable:
    cursor.execute(f"SELECT Package from cvedb5.{linux} where CVE in ({cve_list})")
    deb_pkgnames.update(norm_pkgname(result[0]) for result in cursor.fetchall())

for linux in RPMTable:
    cursor.execute(f"SELECT Package from cvedb5.{linux} where CVE in ({cve_list})")
    rpm_pkgnames.update(norm_pkgname(result[0]) for result in cursor.fetchall())


deb_pkglist = ','.join(f"'{pkg}'" for pkg in sorted(deb_pkgnames))
rpm_pkglist = ','.join(f"'{pkg}'" for pkg in sorted(rpm_pkgnames))

print(f'deb=[{deb_pkglist}]\n\nrpm=[{rpm_pkglist}]')

distro_cves = defaultdict(lambda: set())

# Check CVEs from Ubuntu and Debian
for distro in DEBTable:
    cursor.execute(f"SELECT DISTINCT(cve) from cvedb5.{distro} WHERE NormPackage IN ({deb_pkglist})")
    distro_cves[distro].update(result[0] for result in cursor.fetchall())

# Check CVEs from RedHat, Alma and Rocky Linux
for distro in RPMTable:
    cursor.execute(f"SELECT DISTINCT(cve) from cvedb5.{distro} WHERE NormPackage IN ({rpm_pkglist})")
    distro_cves[distro].update(result[0] for result in cursor.fetchall())

print()
for distro, cves in distro_cves.items():
    print(f'{distro}: CVEs catalogadas: {len(cves)}')

print()
print(f'CVEs cataloged in ubuntupro but not in ubuntu: {len(distro_cves["ubuntupro"] - distro_cves["ubuntu"])}')
print(f'CVEs cataloged in ubuntu but not in ubuntupro: {len(distro_cves["ubuntu"] - distro_cves["ubuntupro"])}')
print(f'CVEs cataloged in ubuntu AND ubuntupro: {len(distro_cves["ubuntu"] & distro_cves["ubuntupro"])}')
print()

comum_cves = distro_cves['debian']
for distro, cves in distro_cves.items():
    if distro == 'ubuntupro':
        continue
    comum_cves &= cves

print(f'CVEs cataloged in ALL distros: {len(comum_cves)}')

# calculate the correction time in days in comum CVES
for distro, cves in distro_cves.items():
    for c in cves:
        if distro == "debian":
            a = distro
            version = ["bullseye", "bookworm", "sid", "trixie"]
            for b in version:
                sql = f"SELECT CVE, Resolved, Published_NIST, Status FROM {a} where Distro IN ('{b}') AND CVE='{c}'"
                main(a, b, sql)
        else:
            if distro == "redhat":
                a = distro
                version = ["6", "7", "8", "9"]
                for b in version:
                    sql = f"SELECT distinct (CVE), Resolved, Published_NIST, FixState FROM {a} where Version IN ('Red Hat Enterprise Linux {b}') AND CVE='{c}' AND FixState NOT LIKE '%not affected%'"
                    main(a, b, sql)
            else:
                if distro == "ubuntu":
                    a = distro
                    version = ["xenial", "bionic", "focal", "jammy"]
                    for b in version:
                        sql = f"SELECT distinct (CVE), Resolved, Published_NIST, Status FROM {a} where Distro IN ('{b}') AND Status != 'not-affected' AND CVE='{c}'"
                        main(a, b, sql)
                else:
                    if distro == "ubuntupro":
                        a = distro
                        version = ["xenial", "bionic", "focal", "jammy"]
                        for b in version:
                            sql = f"SELECT distinct (CVE), Resolved, Published_NIST, Status FROM {a} where Distro IN ('{b}') AND Status != 'not-affected' AND CVE='{c}'"
                            main(a, b, sql)
                    else:
                        if distro == "almalinux":
                            a = distro
                            version = ["8", "9"]
                            for b in version:
                                sql = f"SELECT distinct (CVE), Resolved, Published_NIST FROM {a} where Version IN ('AlmaLinux {b}') AND CVE='{c}'"
                                main(a, b, sql)
                        else:
                            if distro == "rockylinux":
                                a = distro
                                version = ["8", "9"]
                                for b in version:
                                    sql = f"SELECT distinct (CVE), Resolved, Published_NIST FROM {a} where Version IN ('Rocky Linux {b}') AND CVE='{c}'"
                                    main(a, b, sql)

# Printing end of execution
print("Finished")

# Make sure DB´s connection is closed
cursor.close()
mydb.close()
