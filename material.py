# -*- coding: utf-8 -*-

import os
import logging

from ontology import Ontology
from error import * 

class Resource(object):
    def __init__(self, env, location, context):
        self.log = logging.getLogger('Resource')
        self.env = env
        self.context = context
        self.location = location
        self._node = None
        self._knowledge = None

    def __str__(self):
        return str(self.uri)

    @classmethod
    def create(cls, env, location, context):
        resource = None
        if location:
            location = location.project('ns/service/genealogy')
            if 'resource uri' in location:
                if 'home uri' in location:
                    try:
                        resource = globals()[location['implementation']](env, location, context)
                    except TypeError:
                        raise ConfigurationError('unknown implementation class %s', location['implementation'])
                else:
                    raise UnresolvableResourceError('insufficient information to determine resource home uri from location:\n{}'.format(env.to_json(location)))
            else:
                raise UnresolvableResourceError('insufficient information to determine resource uri from location:\n{}'.format(env.to_json(location)))
        return resource

    @property
    def uri(self):
        return self.location['resource uri']

    @property
    def indexed(self):
        return True

    @property
    def local(self):
        return self.location['host'] == self.env.host

    @property
    def remote(self):
        return not self.local

    @property
    def path(self):
        return self.location['path']

    @property
    def host(self):
        return self.location['host']

    @property
    def qualified_path(self):
        if self.local:
            return self.location['path']
        else:
            return self.location['fully qualified path']

    @property
    def exists(self):
        return self.path and os.path.exists(self.path)

    @property
    def node(self):
        if self._node is None:
            self._node = self.env.resolver.resolve(self.uri, self.location, self.context)
        return self._node

    @property
    def knowledge(self):
        if self._knowledge is None:
            self._knowledge = self.env.resolver.resolve(self.location['knowledge uri'], self.location, self.context)
        return self._knowledge

    @property
    def origin(self):
        if self.node is not None and 'head' in self.node and 'genealogy' in self.node['head']:
            return self.node['head']['genealogy']
        else:
            return self.location

    def unload(self):
        if not self.exists:
            self.env.resolver.remove(self.uri)
            self._node = None
