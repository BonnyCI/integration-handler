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
import logging
import os
import platform
import shlex
import subprocess
import sys
import tempfile

import cachecontrol
import iso8601
import jwt
import requests

from bonnyci_integration_handler import tenant
from bonnyci_integration_handler import utils
from bonnyci_integration_handler import version

ACCESS_TOKEN_URL = 'https://api.github.com/installations/%s/access_tokens'

PREVIEW_JSON_ACCEPT = 'application/vnd.github.machine-man-preview+json'

USER_AGENT = "bonnyci-integration-handler/{} {} {}/{}".format(
    version.version_string,
    requests.utils.default_user_agent(),
    platform.python_implementation(),
    platform.python_version())


LOG = logging.getLogger(__name__)


class BonnyIntegrationHandler(object):

    def __init__(self,
                 integration_id,
                 integration_key,
                 invoke=None,
                 template=None,
                 output_file=None):
        self.integration_id = integration_id
        self.integration_key = integration_key
        self.output_file = output_file
        self.invoke = invoke
        self.template = template

        self._installation_token_cache = {}

        self.session = requests.Session()
        self.session.headers['User-Agent'] = USER_AGENT

        # defaults to dictcache - should do something else
        cachecontrol.CacheControl(self.session,
                                  heuristic=utils.DropMaxAgeHeaders())

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
                repositories.append(repo['full_name'])

        return repositories

    def get_config(self):
        repos = self.get_repositories()
        return tenant.write_config(repos, template_file=self.template)

    def write_output(self, config):
        if not self.output_file and not self.invoke:
            LOG.warning("No predefined output file or script to invoke means "
                        "that you are not doing anything with the generated "
                        "output. This seems wrong.")
            return

        if self.output_file:
            fd = open(self.output_file, 'w')
            unlink = False
            output_file = self.output_file
        else:
            fd = tempfile.NamedTemporaryFile(delete=False)
            unlink = True
            output_file = fd.name

        try:
            try:
                fd.write(config)
            finally:
                fd.close()

            if self.invoke:
                args = shlex.split(self.invoke)
                args.append(output_file)
                subprocess.call(args)

        finally:
            if unlink:
                os.unlink(output_file)

    def run(self):
        config = self.get_config()
        self.write_output(config)

    @classmethod
    def register_argparse_arguments(cls, parser):
        parser.add_argument('--integration-id',
                            dest='integration_id',
                            type=int,
                            default=os.environ.get('BIH_INTEGRATION_ID'),
                            help='The Integration ID')

        parser.add_argument('--integration-key',
                            dest='integration_key',
                            default=os.environ.get('BIH_INTEGRATION_KEY'),
                            help='The Integration Key File')

        parser.add_argument('--template',
                            dest='template',
                            default=os.environ.get('BIH_TEMPLATE'),
                            help='A template to insert tenants into')

        parser.add_argument('--invoke',
                            dest='invoke',
                            default=os.environ.get('BIH_INVOKE'),
                            help='A script to invoke when tenant file changed')

        parser.add_argument('--output-file',
                            dest='output_file',
                            default=os.environ.get('BIH_OUTPUT_FILE'),
                            help='The Integration Key File')

    @classmethod
    def load_from_argparse_arguments(cls, opts, **kwargs):
        kwargs.setdefault('integration_id', opts.integration_id)
        kwargs.setdefault('integration_key', opts.integration_key)
        kwargs.setdefault('invoke', opts.invoke)
        kwargs.setdefault('template', opts.template)
        kwargs.setdefault('output_file', opts.output_file)

        if not (kwargs['integration_id'] and kwargs['integration_key']):
            LOG.error('Require both an integration ID and key to function')
            sys.exit(1)

        if not (kwargs['output_file'] or kwargs['invoke']):
            LOG.error("Requires either an output file location or a script to "
                      "invoke. Otherwise you're not doing anything with the "
                      "output.")
            sys.exit(1)

        with open(kwargs['integration_key'], 'r') as f:
            kwargs['integration_key'] = f.read()

        return cls(**kwargs)


def main(argv=None):
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    BonnyIntegrationHandler.register_argparse_arguments(parser)
    opts = parser.parse_args(sys.argv[1:] if argv is None else argv)
    BonnyIntegrationHandler.load_from_argparse_arguments(opts).run()


if __name__ == '__main__':
    main(sys.argv[1:])
