#! /usr/bin/env python3

import os, requests, json, argparse, socket, fcntl, struct
from syslog import syslog, openlog, closelog

parser = argparse.ArgumentParser(description="Update Cloudflare DNS zones through networkd-dispatcher")
parser.add_argument('-c', '--config', default='/etc/dispatch-cloudflare/config.json')
parser.add_argument('-i', '--interactive', action='store_true')
arglist = parser.parse_args()
configfile = arglist.config
interactive = arglist.interactive
config = None

if not interactive:
    openlog ('ddnsdispatcher')

try:
    fd_config = open(configfile)
    config = json.load(fd_config)
except:
    errmsg = "Could not open config file {0}!".format(configfile)
    if interactive:
        print (errmsg)
    else:
        syslog(errmsg)
        closelog()

    exit(-1)

targetstate = 'off'
interface = 'lo'
opstate = 'off'
admstate = 'pending'
v4list = []

statetable = {
        'pending':      'AdministrativeState',
        'configuring':  'AdministrativeState',
        'configured':   'AdministrativeState',
        'unmanaged':    'AdministrativeState',
        'failed':       'AdministrativeState',
        'linger':       'AdministrativeState',
        'off':          'OperationalState',
        'no-carrier':   'OperationalState',
        'dormant':      'OperationalState',
        'carrier':      'OperationalState',
        'degraded':     'OperationalState',
        'routable':     'OperationalState'
}

apiurl = None
apitoken = None
accountid = None
domainlist = None

try:
    apiurl = config['config']['apiurl']
    apitoken = config['config']['apitoken']
    accountid = config['config']['accountid']
    domainlist = config['domains']
except:
    errmsg = 'Missing configuration items in config file. Exiting!'
    if interactive:
        print (errmsg)
    else:
        syslog(errmsg)
        closelog()

    exit(-1)

tmp_zones_to_enum = set()
for domain in domainlist:
    tmp_zones_to_enum.add(domain['zoneid'])

zones_to_enum = list(tmp_zones_to_enum)

cloudflare_headers = { 'Authorization': f"Bearer {apitoken}", 'Content-Type': 'application/json'  }

def getrecord (record: dict):
    zoneid = record['zoneid']
    dnsname = record['dnsname']
    domain_filter = { 'name': dnsname }

    requesturl = f"{apiurl}/{zoneid}/dns_records"

    response = requests.get(requesturl, params=domain_filter, headers=cloudflare_headers)
    result = json.loads(response.text)
    return result

def updaterecord (record, value, rid, rtype='A', ttl=1):
    zoneid = record['zoneid']
    dnsname = record['dnsname']
    requesturl = f"{apiurl}/{zoneid}/dns_records/{rid}"
    updatebody = {"type": rtype, "name": dnsname, "content": value, "ttl": ttl}

    response = requests.put(requesturl, headers=cloudflare_headers, data=json.dumps(updatebody))
    result = json.loads(response.text)
    return result

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))
    )[20:24])

if not interactive:
    targetstate = os.environ['STATE']
    opstate = os.environ['OperationalState']
    admstate = os.environ['AdministrativeState']

for domain in domainlist:
    v4addrs = []
    iface = None
    if interactive:
        iface = domain['interface']
        v4addrs.append(get_ip_address(iface))
    else:
        iface = os.environ['IFACE']
        v4addrs = os.environ['IP_ADDRS'].split(' ')

    goodtogo = False

    if interactive:
        print("Checking domain {0}, pointing to {1}".format(domain['dnsname'], iface))
        if len(v4addrs) > 0:
            print("Interface address(es): {0}".format(v4addrs))
            goodtogo = True
        else:
            print('No IPv4 address available')
    else:
        if statetable[targetstate] == 'OperationalState' and opstate == 'routable' and admstate == 'configured' and iface == domain['interface']:
            syslog("Interface {0} is routable.".format(iface))
            if v4addrs[0] != '':
                syslog("Interface address(es): {0}".format(v4addrs))
                goodtogo = True
            else:
                syslog('No IPv4 address available')

    if goodtogo:
        recordlist = getrecord(domain)
        if (recordlist['success']):
            foundrecord = False
            for record in recordlist['result']:
                if (record['name'] == domain['dnsname'] and record['type'] == 'A'):
                        foundrecord = True
                        currentv4addr = record['content']
                        foundaddr = False
                        for v4addr in v4addrs:
                            if (v4addr == currentv4addr):
                                foundaddr = True
                                break
                        if not foundaddr:
                            updateresult = updaterecord(domain, value=v4addrs[0], rid=record['id'], rtype=record['type'])
                            if (updateresult['success']):
                                msg = 'Successfully updated ' + domain['dnsname'] + ' to point to ' + v4addrs[0]
                                if interactive:
                                    print(msg)
                                else:
                                    syslog(msg)
                            else:
                                msg = 'Could not update ' + domain['dnsname'] + ' record!'
                                if interactive:
                                    print(msg)
                                else:
                                    syslog(msg)
                        else:
                            msg = 'IP address already matches DNS record, no change necessary.'
                            if interactive:
                                print(msg)
                            else:
                                syslog(msg)
                        break
        else:
            msg = 'Failed to check current DNS record!'
            if interactive:
                print(msg)
            else:
                syslog(msg)

if not interactive:
    closelog()
