import whois
import datetime
from itertools import product
import time
import sqlite3

length = 3
alphabet = 'abcdefghijklmnopqrstuvwxyz'
numbers = '0123456789'
tld = ['.com']
now = datetime.datetime.now()
alert_time = datetime.timedelta(days=100)
domains = []
potential = {}

for p in product(alphabet, repeat=length):
    domains.append(''.join(p))

# connect to database
try:
    connection = sqlite3.connect('file:domains.db?mode=rw', uri=True)
except sqlite3.OperationalError:
    with open('db-schema.sql') as schema:
        connection = sqlite3.connect('domains.db')
        cur = connection.cursor()
        cur.executescript(schema.read())
        connection.commit()

for domain in domains:
    complete_domain = domain + tld[0]

    # check for existing record in database to prevent hitting WHOIS server
    connection = sqlite3.connect('domains.db')
    cur = connection.cursor()
    cur.execute('SELECT COUNT(*) FROM Domains WHERE Domain = ?', (complete_domain, ))
    result = cur.fetchone()[0]
    if result != 0:
        print(complete_domain + ' is already present in database.')
        continue

    # otherwise proceed to obtain WHOIS details and save to database
    result = whois.whois(complete_domain)

    # handle inconsistent returns from WHOIS
    if type(result['creation_date']) is list:
        creation_date = result['creation_date'][0]
    else:
        creation_date = result['creation_date']

    if type(result['expiration_date']) is list:
        expiration_date = result['expiration_date'][0]
    else:
        expiration_date = result['expiration_date']

    time_remaining = expiration_date - now

    connection = sqlite3.connect('domains.db')

    # save result to database
    cur = connection.cursor()
    cur.execute('INSERT INTO Domains (Domain, Created, Expires, Remaining) VALUES (?, ?, ?, ?)',
                (complete_domain, creation_date, expiration_date, str(time_remaining)))
    connection.commit()

    print(complete_domain)
    print('Created: ' + str(creation_date))
    print('Expires: ' + str(expiration_date))
    print(str(time_remaining).split(',')[0] + ' days remaining')
    if time_remaining < alert_time:
        print(complete_domain.upper() + ' EXPIRING IN ' + str(time_remaining).split(',')[0].upper())
    print('*' * 50)
    time.sleep(1) # no idea what the VeriSign rate limit is but using 1 second for now
