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


API_URL = 'https://api.linode.com/v4'


def request(method, endpoint, send_data={}, *args, **kwargs):
    headers = {'Authorization': f'Bearer {api_key}'}
    if send_data:
        headers['Content-Type'] = 'application/json'
        kwargs['json'] = send_data

    ret = requests.request(method, API_URL + endpoint, headers=headers,
                        *args, **kwargs).json()
    if 'errors' in ret:
        raise RequestException(
            'API error: {!s}'.format(ret['errors']),
            data=ret['errors']
        )
    return ret


def generate_acme_challenge_records(records):
    """
    Make Resource objects for a given set of acme challenge domains

    Parameters:
    records -- {'example.com': 'aBcD...'} dict where the key is the FQDN to
               set _acme-challenge on and the value is the value of the TXT
               record to be set
    """
    # "Note that domain names containing wildcards must have the wildcard
    # component removed in the corresponding TXT record"
    resources = []
    for (k, v) in records.items():
        name = '_acme-challenge.' + k.replace('*.', '')
        resources.append(Resource(name, 'TXT', v))
    return resources


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
    def __init__(self, id, domain, **kwargs):
        """
        Make an API domain abstraction

        Params:
        id -- linode-assigned id for this domain
        domain -- name of the domain

        Keyword parameters:
        Directly assigned into self.data, so this can be used with the
        **-operator with data from the API
        """
        self.domain_id = int(id)
        self.name = domain
        self.data = kwargs

    def create_resource(self, res):
        """
        Create a resource on Linode

        Parameters:
        res -- resource to create

        Returns:
        The resource given with all parameters filled from online
        """
        print('=====create_resource======')
        data = res._convert_to_wire_format()
        print(data)
        filled_res = request('POST', f'/domains/{self.domain_id}/records', send_data=data)
        print(filled_res)
        return Resource(domain_id=self.domain_id, **filled_res)

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
        data = request('GET', '/domains')['data']
        domains = [Domain(**dom) for dom in data]

        return domains


class Resource:
    def __init__(self, name, type, target, id=None,
                 domain_id=None, ttl_sec=None, **kwargs):
        """
        Make an API resource abstraction

        Params:
        name -- name of resource
        type -- dns record type
        target -- response for this resource (e.g. ip address)
        id -- ID for this resource if it was fetched from the API
        domain_id -- domain this is attached to
        ttl_sec -- ttl for this resource
        """
        self.name = name
        # uppercase because api seems to return random case
        self.res_type = type.upper()
        self.target = target
        self.resource_id = id
        self.domain_id = domain_id
        self.ttl = ttl_sec
        self.data = kwargs

    def __repr__(self):
        return '{r.__class__.__name__}({r.name!r}, {r.res_type!r}, ' \
               '{r.target!r}, resource_id={r.resource_id!r}, ' \
               'domain_id={r.domain_id}, ttl={r.ttl!r})'.format(r=self)

    def _convert_to_wire_format(self):
        ok_fields = {
            'id',
            'type',
            'name',
            'target',
            'type',
            'priority',
            'weight',
            'port',
            'service',
            'protocol',
            'tag',
            'ttl_sec',
        }
        data = self.__dict__.copy()
        data.update(data['data'])
        data['type'] = data['res_type']
        return {k: v for (k, v) in data.items() if k in ok_fields and v}

    def update(self):
        """
        Send the current version of this Resource to Linode to update it
        """
        data = self._convert_to_wire_format()
        return request('PUT', f'/domains/{self.domain_id}/records/{self.resource_id}', send_data=data)

    def delete(self):
        """
        Delete this record from Linode servers
        """
        return request('DELETE', f'/domains/{self.domain_id}/records/{self.resource_id}')

    @classmethod
    def get(cls, domain_id, resource_id=None):
        """
        Pull resource data for a domain or specific resource
        """
        endpoint = f'/domains/{domain_id}/records/{resource_id}' if resource_id else f'/domains/{domain_id}/records'

        data = request('GET', endpoint)['data']
        return [Resource(domain_id=domain_id, **res) for res in data]


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
    ap.add_argument(
        '--acme-challenge',
        nargs=2,
        metavar=('domain_id', 'challenges_path'),
        help='Read the given JSON file following the format in acmebot'
        'documentation and make appropriate TXT records'
    )
    ap.add_argument('--update', nargs=2, metavar=('domain_id', 'resource_id'),
                    type=int, help='Update DNS in this record')
    ap.add_argument('--ip', '--value', default='auto', help='Update ip to this. '
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

    if args.list_domains:
        pprint(Domain.list())
        exit(0)
    elif args.list_dom_resources:
        pprint(Domain(args.list_dom_resources, '').resources)
        exit(0)
    elif args.acme_challenge:
        dom_id = int(args.acme_challenge[0])
        challenges_file = args.acme_challenge[1]

        dom = Domain(dom_id, '')
        existing_resources = [res for res in Resource.get(dom_id) if res.name.startswith('_acme-challenge')]
        print('Removing existing records:')
        pprint(existing_resources)
        for res in existing_resources:
            res.delete()
        with open(challenges_file) as h:
            records = generate_acme_challenge_records(json.load(h))
        pprint(records)
        resources = [dom.create_resource(rec) for rec in records]
        pprint(resources)
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
        exit(0)


if __name__ == '__main__':
    main()
