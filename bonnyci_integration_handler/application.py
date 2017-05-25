# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import datetime
import hashlib
import hmac
import logging
import os
import platform
import sys

import cachecontrol
import ipaddress
import iso8601
import jwt
import requests
import webob
import webob.dec
import webob.exc

from bonnyci_integration_handler import tenant
from bonnyci_integration_handler import utils
from bonnyci_integration_handler import version

ACCESS_TOKEN_URL = 'https://api.github.com/installations/%s/access_tokens'
GITHUB_META_URL = 'https://api.github.com/meta'

PREVIEW_JSON_ACCEPT = 'application/vnd.github.machine-man-preview+json'

ALLOWED_EVENTS = frozenset(['integration_installation',
                            'integration_installation_repositories'])

USER_AGENT = "bonnyci-integration-handler/{} {} {}/{}".format(
    version.version_string,
    requests.utils.default_user_agent(),
    platform.python_implementation(),
    platform.python_version())


LOG = logging.getLogger(__name__)


class Request(webob.Request):

    _event_data = None

    @property
    def event_type(self):
        return self.headers.get('X-Github-Event')

    @property
    def event_data(self):
        """Cache the JSON body so as not to interpret it each time."""
        if self._event_data is None:
            self._event_data = self.json_body

        return self._event_data

    @property
    def signature(self):
        return self.headers.get('X-Hub-Signature')


class BonnyIntegrationHandler(object):

    def __init__(self,
                 integration_id,
                 integration_key,
                 output_file=None,
                 webhook_key=None,
                 debug=False):
        self.integration_id = integration_id
        self.integration_key = integration_key
        self.output_file = output_file
        self.webhook_key = webhook_key
        self.debug = debug

        self._installation_token_cache = {}

        self.session = requests.Session()
        self.session.headers['User-Agent'] = USER_AGENT

        # defaults to dictcache - should do something else
        cachecontrol.CacheControl(self.session,
                                  heuristic=utils.DropMaxAgeHeaders())

    def validate_request(self, request):
        if request.path != '/':
            raise webob.exc.HTTPNotFound()

        if request.method != 'POST':
            raise webob.exc.HTTPMethodNotAllowed()

        if request.event_type not in ALLOWED_EVENTS:
            raise webob.exc.HTTPBadRequest()

    def validate_signature(self, request):
        signature = request.headers.get('X-Hub-Signature')

        if self.webhook_key and not signature:
            raise webob.exc.HTTPForbidden()

        elif signature and not self.webhook_key:
            raise webob.exc.HTTPForbidden()

        elif self.webhook_key:
            digest, value = signature.split('=')

            if digest != 'sha1':
                raise webob.exc.HTTPForbidden()

            mac = hmac.new(self.webhook_key,
                           msg=request.body,
                           digestmod=hashlib.sha1)

            if not hmac.compare_digest(mac.hexdigest(), value):
                raise webob.exc.HTTPForbidden()

    def validate_ip(self, request):
        request_ip = ipaddress.ip_address(request.client_addr.decode('utf-8'))
        hook_blocks = self.session.get(GITHUB_META_URL).json()['hooks']

        for block in hook_blocks:
            if request_ip in ipaddress.ip_network(block):
                break
        else:
            raise webob.exc.HTTPForbidden()

    def _get_integration_token(self):
        now = utils.now()
        expiry = now + datetime.timedelta(minutes=5)
        data = {'iat': now, 'exp': expiry, 'iss': self.integration_id}
        return jwt.encode(data, self.integration_key, algorithm='RS256')

    def _get_installation_token(self, url, integration_token):
        headers = {'Accept': PREVIEW_JSON_ACCEPT,
                   'Authorization': 'Bearer %s' % integration_token}

        response = self.session.post(url, headers=headers)
        response.raise_for_status()

        data = response.json()
        expiry = iso8601.parse_date(data['expires_at'])
        expiry -= datetime.timedelta(minutes=2)
        return data['token'], expiry

    def _get_cached_installation_token(self,
                                       installation_id,
                                       url=None,
                                       integration_token=None):
        # i pulled this from zuul - but do we need to cache for tokens now?

        now = utils.now()
        token, expiry = self._installation_token_cache.get(installation_id,
                                                           (None, None))

        if ((not expiry) or (not token) or (now >= expiry)):
            token, expiry = self._get_installation_token(
                url or ACCESS_TOKEN_URL % installation_id,
                integration_token or self._get_integration_token())

            self._installation_token_cache[installation_id] = (token, expiry)

        return token

    def _get_iter(self, path, key=None, **kwargs):
        """Iterate over multiple 'next' responses to get all items."""
        while path:
            response = self.session.get(path, **kwargs)
            response.raise_for_status()

            json_data = response.json()

            if key:
                json_data = json_data[key]

            for item in json_data:
                yield item

            path = response.links.get('next')

    def get_repositories(self):
        repositories = []

        integration_token = self._get_integration_token()

        url = 'https://api.github.com/integration/installations'
        headers = {'Accept': PREVIEW_JSON_ACCEPT,
                   'Authorization': 'Bearer %s' % integration_token}

        installations = self._get_iter(url, headers=headers)

        for installation in installations:
            installation_token = self._get_cached_installation_token(
                installation['id'],
                url=installation['access_tokens_url'],
                integration_token=integration_token)

            headers = {'Accept': PREVIEW_JSON_ACCEPT,
                       'Authorization': 'Bearer %s' % installation_token}

            repo_iter = self._get_iter(installation['repositories_url'],
                                       headers=headers,
                                       key='repositories')

            for repo in repo_iter:
                repositories.append('github.com/%s' % repo['full_name'])

        return repositories

    def get_config(self):
        return tenant.write_config(self.get_repositories())

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        if self.debug:
            # respond to any http request with the yaml output
            headers = {'Content-Type': 'application/yaml'}
            return webob.Response(headers=headers, body=self.get_config())

        else:
            self.validate_request(request)
            self.validate_ip(request)
            self.validate_signature(request)

            config = self.get_config()

            with open(self.output_file, 'w') as f:
                f.write(config)

            # need to either SIGHUP or send a message over socket here to
            # reload zuul config

            headers = {'Content-Type': 'application/text'}
            return webob.Response(headers=headers, body='Success')


def initialize_application(argv=None):
    parser = argparse.ArgumentParser()

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        default=os.environ.get('BIH_DEBUG'),
                        help='Debug mode. Will return the config output.')

    parser.add_argument('--integration-id',
                        dest='integration_id',
                        type=int,
                        default=os.environ.get('BIH_INTEGRATION_ID'),
                        required=True,
                        help='The Integration ID')

    parser.add_argument('--integration-key',
                        dest='integration_key',
                        default=os.environ.get('BIH_INTEGRATION_KEY'),
                        required=True,
                        help='The Integration Key File')

    parser.add_argument('--output-file',
                        dest='output_file',
                        default=os.environ.get('BIH_OUTPUT_FILE'),
                        help='The Integration Key File')

    parser.add_argument('--webhook-key',
                        dest='webhook_key',
                        default=os.environ.get('BIH_WEBHOOK_KEY'),
                        help='Symmetric key to validate webhook signatures')

    opts = parser.parse_args(sys.argv[1:] if argv is None else argv)

    with open(opts.integration_key, 'r') as f:
        integration_key = f.read()

    return BonnyIntegrationHandler(integration_id=opts.integration_id,
                                   integration_key=integration_key,
                                   debug=opts.debug,
                                   output_file=opts.output_file,
                                   webhook_key=opts.webhook_key)
