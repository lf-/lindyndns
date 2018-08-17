#!/usr/bin/env python3
import requests
import json
import logging
import sys

secrets_files = ('./lindyndns.apikey', '/etc/lindyndns.apikey')
for f in secrets_files:
    try:
        with open(f) as h:
            api_key = h.read().rstrip()
            break
    except FileNotFoundError:
        continue
else:
    api_key = None


APP_NAME = 'lindyndns'

log = logging.getLogger(APP_NAME)

fmt = logging.Formatter(
    '{asctime} {levelname} {filename}:{lineno}: {message}',
    datefmt='%b %d %H:%M:%S',
    style='{'
)
# don't add handlers repeatedly when I use autoreload
for handler in log.handlers:
    if isinstance(handler, logging.StreamHandler):
        break
else:
    hnd = logging.StreamHandler(sys.stderr)
    hnd.setFormatter(fmt)
    log.addHandler(hnd)


API_URL = 'https://api.linode.com/v4'


def request(method, endpoint, send_data={}, *args, **kwargs):
    headers = {'Authorization': f'Bearer {api_key}'}
    if send_data:
        headers['Content-Type'] = 'application/json'
        kwargs['json'] = send_data

    log.debug('Requesting %r', endpoint)
    ret = requests.request(method, API_URL + endpoint, headers=headers,
                        *args, **kwargs).json()
    log.debug('Got %r', ret)
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
        data = res._convert_to_wire_format()
        log.debug('Creating resource %r', data)
        filled_res = request('POST', f'/domains/{self.domain_id}/records', send_data=data)
        log.debug('Filled version: %r', filled_res)
        return Resource(domain_id=self.domain_id, **filled_res)

    def __repr__(self):
        return '{d.__class__.__name__}({d.domain_id!r}, ' \
               '{d.name!r})'.format(d=self)

    def resources(self):
        """
        List resources for a domain
        """
        endpoint = f'/domains/{self.domain_id}/records'

        data = request('GET', endpoint)['data']
        return [Resource(domain_id=self.domain_id, **res) for res in data]

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
    def get(cls, domain_id, resource_id):
        """
        Pull resource data for a specific resource
        """
        endpoint = f'/domains/{domain_id}/records/{resource_id}'

        res = request('GET', endpoint)
        return Resource(domain_id=domain_id, **res)


def main(in_args=sys.argv[1:]):
    import argparse
    import sys
    from pprint import pprint, pformat
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
    ap.add_argument('--log-level', help='Log level to use (default: INFO)',
                    default='INFO')

    args = ap.parse_args(in_args)

    log.setLevel(args.log_level)

    if not api_key:
        log.error('Please create one of %s with the contents of '
                  'your linode API key.', secrets_files)
        exit(1)

    if args.list_domains:
        pprint(Domain.list())
        exit(0)
    elif args.list_dom_resources:
        pprint(Domain(args.list_dom_resources, '').resources())
        exit(0)
    elif args.acme_challenge:
        dom_id = int(args.acme_challenge[0])
        challenges_file = args.acme_challenge[1]

        dom = Domain(dom_id, '')
        existing_resources = [res for res in dom.resources() if res.name.startswith('_acme-challenge')]
        log.info('Removing existing records: %s', pformat(existing_resources))
        for res in existing_resources:
            res.delete()
        with open(challenges_file) as h:
            records = generate_acme_challenge_records(json.load(h))
        log.info('Generated records: %s', pformat(records))
        resources = [dom.create_resource(rec) for rec in records]
        log.info('Linode now has %s', pformat(resources))
        exit(0)
    elif args.update:
        if args.ip == 'auto':
            ip_addr = get_ip(method=args.ip_method, ifname=args.interface)
        else:
            ip_addr = args.ip
        log.info('Updating dynamic dns to %s', ip_addr)
        res = Resource.get(args.update[0], args.update[1])
        log.info('Currently %r', res)
        res.target = ip_addr
        log.info('Will be %r', res)
        res.update()
        exit(0)


if __name__ == '__main__':
    main()
