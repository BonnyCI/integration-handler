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

import datetime

from cachecontrol import heuristics as cachecontrol_heuristics


class DropMaxAgeHeaders(cachecontrol_heuristics.BaseHeuristic):
    """A CacheControl strategy that only cares about Etags.

    CacheControl will prioritize the max-age headers from our github responses
    over the ETag, causing all caching to be time-based and only refresh every
    60 seconds.  Stripping them out here forces the library to use the ETag
    headers and a conditional request when determining freshness of existing
    cache entries.
    """

    # NOTE: This was taken from the github connection in zuul and should be
    # somehow kept in sync. They'll both suffer from any problems.

    def update_headers(self, response):
        cc_header = response.headers.get('cache-control')
        if not cc_header:
            return {}

        cc_new_header = []
        for cc in [h.strip() for h in cc_header.split(',')]:
            if not cc.startswith('max-age') and not cc.startswith('s-maxage'):
                cc_new_header.append(cc)

        return {'cache-control': ', '.join(cc_new_header)}


class UTC(datetime.tzinfo):
    """UTC Timezone from python docs"""

    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


def now():
    """UTC aware now"""
    return datetime.datetime.now(UTC())
