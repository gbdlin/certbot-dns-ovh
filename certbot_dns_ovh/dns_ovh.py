"""DNS Authenticator for OVH API DNS."""
import json
import logging

import zope.interface
import ovh

from ovh.client import ENDPOINTS

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for OVH API DNS

    This Authenticator uses the OVH API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using OVH DNS for DNS).')
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('endpoint',
            help='Endpoint to which OVH API Client should connect',
            choices=ENDPOINTS.keys(),
            default=None)
        add('application_key',
            help='Public key of your application',
            default=None)
        add('application_secret',
            help='Private key of your application',
            default=None)
        add('consumer_key',
            help='API key of your account',
            default=None)
        add('config_file',
            help='Config file with OVH credentials',
            default=None)

    def more_info(self): # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Google Cloud DNS API.'

    def _setup_credentials(self):
        if (self.conf('endpoint') is None or self.conf('application_key') is None or
            self.conf('application_secret') is None or self.conf('consumer_key') is None) and \
            self.conf('config_file') is None:
                raise errors.PluginError('Unable to determine correct credentials. You should either '
                                         'provide --dns-ovh-endpoint, --dns-ovh-application_key, '
                                         '--dns-ovh-application_secret and --dns-ovh-consumer key or '
                                         '--dns-ovh-config_file')
        else:
            self._client = ovh.Client(
                endpoint=self.conf('endpoint'), application_key=self.conf('application_key'),
                application_secret=self.conf('application_secret'),
                consumer_key=self.conf('consumer_key'), config_file=self.conf('config_file')
            )
    def _perform(self, domain, validation_name, validation):
        dns_zones = self._client.get('/domain/zone')
        dns_zones = sorted(filter(domain.startswith, dns_zones), key=len, reverse=True)
        if not len(dns_zones):
            raise errors.PluginError('Suitable DNS zone not found on provided account')

        dns_zone = dns_zones[0]
        self._dns_zone = dns_zone
        dns_zone_details = self._client.get('/domain/zone/{}'.format(dns_zone))
        subdomain_part = domain[:-len(dns_zone)-1]
        subdomain = '{}.{}'.format(validation_name, subdomain_part) if subdomain_part else validation_name
        
        existing_keys = self._client.get('/domain/zone/{}/record?fieldType=TXT&subDomain={}'.format(
            dns_zone, subdomain))
        if existing_keys:
            self._client.put('/domain/zone/{}/record/{}'.format(dns_zone, existing_keys[0]),
                             subDomain=subdomain, target=validation, ttl=60)
            self._dns_record_id = existing_keys[0]
            for id_ in existing_keys[1:]:
                self._client.delete('/domain/zone/{}/record/{}'.format(dns_zone, id_))
        else:
            new_record_data = self._client.post('/domain/zone/{}/record'.format(dns_zone),
                                                subDomain=subdomain, fieldType='TXT',
                                                target=validation, ttl=60)
            self._dns_record_id = new_record_data['id']
        self._client.post('/domain/zone/{}/refresh'.format(dns_zone))

    def _cleanup(self, domain, validation_name, validation):
        self._client.delete('/domain/zone/{}/record/{}'.format(
            self._dns_zone, self._dns_record_id))
        self._client.post('/domain/zone/{}/refresh'.format(self._dns_zone))
