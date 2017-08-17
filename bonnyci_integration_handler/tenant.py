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
        - BonnyCI/project-config
"""


def generate_bonny(repos, item):
    if item.get('tenant', {}).get('name') != 'BonnyCI':
        return item

    source = item.get('tenant', {}).get('source', {}).copy()

    gh = source.pop('github', {})
    config_projects = gh.get('config-projects', [])
    untrusted_projects = gh.get('untrusted-projects', [])

    # don't include any config-projects in new untrusted list
    repos = set(repos) - set(config_projects)

    # our new untrusted is anything in the template and all fetched
    new_untrusted_projects = set(untrusted_projects) | repos

    source['github'] = {
        'config-projects': config_projects,
        'untrusted-projects': sorted(new_untrusted_projects)
    }

    return {
        'tenant': {
            'name': 'BonnyCI',
            'source': source,
        }
    }


def write_config(repos, template_file=None):
    base = None

    if template_file:
        try:
            with open(template_file, 'r') as f:
                base = yaml.safe_load(f)
        except IOError:
            LOG.exception("Failed to open template file, "
                          "falling back to default.")

    if not base:
        base = yaml.safe_load(BASE_TEMPLATE)

    config = [generate_bonny(repos, i) for i in base]
    return yaml.safe_dump(config, encoding='utf-8', default_flow_style=False)
