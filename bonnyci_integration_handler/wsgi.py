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
import hashlib
import hmac
import os
import sys

import ipaddress
import webob
import webob.dec
import webob.exc

from bonnyci_integration_handler import application

GITHUB_META_URL = 'https://api.github.com/meta'

ALLOWED_EVENTS = frozenset(['installation', 'installation_repositories'])


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


class BonnyIntegrationRequestHandler(object):

    def __init__(self, app, webhook_key):
        self.app = app
        self.webhook_key = webhook_key

    def validate_request(self, request):
        if request.path != '/integration/':
            raise webob.exc.HTTPNotFound()

        if request.method != 'POST':
            raise webob.exc.HTTPMethodNotAllowed()

        if request.event_type not in ALLOWED_EVENTS:
            raise webob.exc.HTTPBadRequest()

    def validate_signature(self, request):
        if self.webhook_key and not request.signature:
            raise webob.exc.HTTPForbidden()

        elif request.signature and not self.webhook_key:
            raise webob.exc.HTTPForbidden()

        elif self.webhook_key:
            digest, value = request.signature.split('=')

            if digest != 'sha1':
                raise webob.exc.HTTPForbidden()

            mac = hmac.new(self.webhook_key,
                           msg=request.body,
                           digestmod=hashlib.sha1)

            if not hmac.compare_digest(mac.hexdigest(), value):
                raise webob.exc.HTTPForbidden()

    def validate_ip(self, request):
        request_ip = ipaddress.ip_address(request.client_addr.decode('utf-8'))
        hook_blocks = self.app.session.get(GITHUB_META_URL).json()['hooks']

        for block in hook_blocks:
            if request_ip in ipaddress.ip_network(block):
                break
        else:
            raise webob.exc.HTTPForbidden()

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        self.validate_request(request)
        self.validate_ip(request)
        self.validate_signature(request)

        self.app.run()

        headers = {'Content-Type': 'application/text'}
        return webob.Response(headers=headers, body='Success')

    @classmethod
    def register_argparse_arguments(cls, parser):
        parser.add_argument(
            '--webhook-key',
            dest='webhook_key',
            default=os.environ.get('BIH_WEBHOOK_KEY'),
            help='Symmetric key to validate webhook signatures')

    @classmethod
    def load_from_argparse_arguments(cls, opts, **kwargs):
        kwargs.setdefault('webhook_key', opts.webhook_key)
        return cls(**kwargs)


def main(argv=None):
    parser = argparse.ArgumentParser()
    application.BonnyIntegrationHandler.register_argparse_arguments(parser)
    BonnyIntegrationRequestHandler.register_argparse_arguments(parser)
    opt = parser.parse_args(sys.argv[1:] if argv is None else argv)
    app = application.BonnyIntegrationHandler.load_from_argparse_arguments(opt)

    return BonnyIntegrationRequestHandler.load_from_argparse_arguments(opt,
                                                                       app=app)
