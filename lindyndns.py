#!/usr/bin/env python3
import requests
import json
import sys

secrets_files = ('./lindyndns.apikey', '/etc/lindyndns.apikey')
# find an api key, error out if the user forgot to make a file with one
for f in secrets_files:
    try:
        with open(f) as h:
            api_key = h.read().rstrip()
            break
    except FileNotFoundError:
        continue
else:
    api_key = None

API_URL = 'https://api.linode.com/'


def request(action, data={}, *args, **kwargs):
    send_data = {
        'api_key': api_key,
        'api_action': action
    }
    send_data.update(data)
    ret = requests.post(API_URL, send_data, *args, **kwargs).json()
    if len(ret['ERRORARRAY']) > 0:
        raise RequestException('API error: {!s}'.format(ret['ERRORARRAY']),
                               data=ret['ERRORARRAY'])
    return ret


def get_ip(method='http', ifname=None):
    """
    Get the public IP address of a machine

    Params:
    method -- method to use. Can be 'http', or 'socket'
    """
    if method == 'http':
        return requests.get('http://ip.42.pl/raw').content.decode()
    elif method == 'socket':
        # Only works on Linux!
        if sys.platform != 'linux':
            raise EnvironmentError("ip method 'socket' only supported on "
                                   "Linux!")
        if not ifname:
            raise LinodeException("No interface name provided and using "
                                  "ip method 'socket'!")
        import socket
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack(b'256s', ifname[:15].encode())
        )[20:24])
    elif method == 'netifaces':
        if not ifname:
            raise LinodeException("No interface name provided and using "
                                  "ip method 'netifaces'!")
        import netifaces as ni
        return ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']


class LinodeException(Exception):
    def __init__(self, msg, data={}):
        self.data = data
        super(Exception, self).__init__(msg)


class RequestException(LinodeException):
    pass


class Domain:
    def __init__(self, domain_id, name):
        """
        Make an API domain abstraction

        Params:
        domain_id -- linode-assigned id for this domain
        name -- name of the domain
        """
        self.domain_id = domain_id
        self.name = name

    def __repr__(self):
        return '{d.__class__.__name__}({d.domain_id!r}, ' \
               '{d.name!r})'.format(d=self)

    @property
    def resources(self):
        """
        List resources for a domain
        """
        return Resource.get(self.domain_id)

    @staticmethod
    def list():
        """
        List domains viewable by the user whose api key is in use
        """
        data = request('domain.list')['DATA']
        domains = []

        for dom in data:
            domains.append(Domain(dom['DOMAINID'], dom['DOMAIN']))

        return domains


class Resource:
    def __init__(self, name, res_type, target, resource_id=None,
                 domain_id=None, ttl=None, **kwargs):
        """
        Make an API resource abstraction

        Params:
        name -- name of resource
        res_type -- dns record name
        target -- response for this resource (e.g. ip address)
        resource_id -- ID for this resource if it was fetched from the API
        domain_id -- domain this is attached to
        ttl -- ttl for this resource
        """
        self.name = name
        # uppercase because api seems to return random case
        self.res_type = res_type.upper()
        self.target = target
        self.resource_id = resource_id
        self.domain_id = domain_id
        self.ttl = ttl

    def __repr__(self):
        return '{r.__class__.__name__}({r.name!r}, {r.res_type!r}, ' \
               '{r.target!r}, resource_id={r.resource_id!r}, ' \
               'domain_id={r.domain_id}, ttl={r.ttl!r})'.format(r=self)

    def update(self):
        """
        Send the current version of this Resource to Linode to update it
        """
        translation = {
            'name': 'Name',
            'resource_id': 'ResourceID',
            'domain_id': 'DomainID',
            'target': 'Target',
            'ttl': 'TTL_sec',
            'res_type': 'Type'
        }
        request('domain.resource.update',
                {translation.get(x, x): y for x, y in self.__dict__.items()})

    @classmethod
    def get(cls, domain_id, resource_id=None):
        """
        Pull resource data for a domain or specific resource
        """
        req_body = {'DomainID': domain_id}
        if resource_id:
            req_body.update({'ResourceID': resource_id})

        data = request('domain.resource.list',
                       req_body)['DATA']
        return [cls.from_api_format(res) for res in data]

    @staticmethod
    def from_api_format(data):
        """
        Take a resource, from the api, in unserialized JSON, convert to
        a Resource
        """
        translation = {
            'NAME': 'name',
            'RESOURCEID': 'resource_id',
            'DOMAINID': 'domain_id',
            'TARGET': 'target',
            'TTL_SEC': 'ttl',
            'TYPE': 'res_type'
        }
        return Resource(**{translation.get(x, x): y for x, y in data.items()})


def main():
    import argparse
    import sys
    from pprint import pprint
    ap = argparse.ArgumentParser(
        description='Simple Linode DNS API client for dynamic dns'
    )
    ap.add_argument('--list-domains', action='store_true',
                    help='List all domains and their IDs')
    ap.add_argument('--list-dom-resources', metavar='domain_id', type=int,
                    help='List resources for a given domain ID')
    ap.add_argument('--update', nargs=2, metavar=('domain_id', 'resource_id'),
                    type=int, help='Update DNS in this record')
    ap.add_argument('--ip', default='auto', help='Update ip to this. '
                                                 'Default is auto.')
    ap.add_argument('--ip-method', choices=('http', 'socket', 'netifaces'),
                    default='http', help='Method to get IP address')
    ap.add_argument('--interface', help='Interface to use to get ip address. '
                    'Only relevant to socket/netifaces methods.')

    if not (len(sys.argv) > 1):
        ap.print_help()
        exit(1)

    args = ap.parse_args()

    if not api_key:
        print('Please create one of', secrets_files, ' with the contents of '
              'your linode API key.')
        exit(1)

    if args.listdomains:
        pprint(Domain.list())
        exit(0)
    elif args.list_dom_resources:
        pprint(Domain(args.list_dom_resources, '').resources)
        exit(0)
    elif args.update:
        if args.ip == 'auto':
            ip_addr = get_ip(method=args.ip_method, ifname=args.interface)
        else:
            ip_addr = args.ip
        print('Updating dynamic dns to', ip_addr)
        res = Resource.get(args.update[0], args.update[1])[0]
        print('Currently', res)
        res.target = ip_addr
        print('Will be', res)
        print('Updating...')
        res.update()


if __name__ == '__main__':
    main()
