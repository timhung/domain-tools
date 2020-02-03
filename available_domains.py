import whois
import datetime
from itertools import product

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

for domain in domains:
    complete_domain = domain + tld[0]
    result = whois.whois(complete_domain)
    if type(result['creation_date']) is list:
        creation_date = result['creation_date'][0]
    else:
        creation_date = result['creation_date']
    if type(result['expiration_date']) is list:
        expiration_date = result['expiration_date'][0]
    else:
        expiration_date = result['expiration_date']
    time_remaining = expiration_date - now
    print(complete_domain)
    print('Created: ' + str(creation_date))
    print('Expires: ' + str(expiration_date))
    print(str(time_remaining).split(',')[0] + ' days remaining')
    if time_remaining < alert_time:
        print(complete_domain.upper() + ' EXPIRING IN ' + str(time_remaining).split(',')[0].upper())
    print('*' * 50)
