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

import yaml


BASE_TEMPLATE = """
- tenant:
    name: BonnyCI
    source:
      github:
        config-projects:
        - github.com/BonnyCI/project-config
"""


def generate_bonny(repos, item):
    if item.get('tenant', {}).get('name') != 'BonnyCI':
        return item

    gh = item.get('tenant', {}).get('source', {}).get('github', {})

    config = gh.get('config-projects', [])

    # don't include and config-projects in new untrusted list
    repos = set(repos) - set(config)

    # our new untrusted is anything in the template and all fetched
    untrusted = set(gh.get('untrusted-projects', [])) | repos

    return {
        'tenant': {
            'name': 'BonnyCI',
            'source': {
                'github': {
                    'config-projects': config,
                    'untrusted-projects': sorted(untrusted)
                }
            }
        }
    }


def write_config(repos, template_file=None):
    if template_file:
        with open(template_file, 'r') as f:
            base = yaml.safe_load(f)
    else:
        base = yaml.safe_load(BASE_TEMPLATE)

    config = [generate_bonny(repos, i) for i in base]
    return yaml.safe_dump(config, encoding='utf-8', default_flow_style=False)
