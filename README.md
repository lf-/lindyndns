# lindyndns
lindyndns is a simple dynamic dns client for Linode. The official one is a bit long in the tooth, as it hasn't been updated since 2009, although it is admittedly much smaller.

## How to use it

* Put lindyndns.py someplace and mark it executable

* Put a file named lindyndns.apikey in the same directory or in /etc.

* Set sensible permissions for that file so that random people can't mess with your DNS (optional)

### Run it
    # find your domain
    lindyndns.py --list-domains
    # find the appropriate resource id
    lindyndns.py --list-dom-resources 12345 #replace 12345 with your actual domain id
    # update it
    lindyndns.py --update 12345 67890 #12345 is the domain id, 67890 is the resource id

## Usage

    usage: lindyndns.py [-h] [--list-domains] [--list-dom-resources domain_id]
                        [--update domain_id resource_id] [--ip IP]
                        [--ip-method {http,socket}] [--interface INTERFACE]

    Simple Linode DNS API client for dynamic dns

    optional arguments:
      -h, --help            show this help message and exit
      --list-domains         List all domains and their IDs
      --list-dom-resources domain_id
                            List resources for a given domain ID
      --update domain_id resource_id
                            Update DNS in this record
      --ip IP               Update ip to this. Default is auto.
      --ip-method {http,socket}
                            Method to get IP address
      --interface INTERFACE
                            Interface to use to get ip address.Only relevant to
                            socket method.
