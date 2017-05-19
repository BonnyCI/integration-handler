===========================
bonnyci-integration-handler
===========================

Handle integration events from github in a BonnyCI specific way.

There are a hundred ways we can and probably should improve this in future but
for now what we really need is something that works.

* Free software: Apache license
* Source: https://github.com/bonnyci/integration-handler

TODO:
-----

- Probably should back it onto celery or some sort of worker instead of doing
  the processing in a request handler.

- Write to zookeeper or some sort of state keeper and have a listener that
  writes the config to zuul and updates when state is changed rather than
  having webapps touch zuul config files.

- Actually look at the events that are submitted to us and use that to modify
  the config rather than re-read our entire state from github each time.

- Some sort of rate limit.

- Cache tokens and requests to memcache (or other) instead of per-process.
