# -*- coding: utf-8 -*-

from service import ResourceHandler
from ontology import Ontology, Document

class HomeHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        resolved = False
        self.assign_key(query.genealogy, 'uuid', 'local', query.branch)
        if 'depend' in query.match:
            query.genealogy['language']
            try:
                dependee = self.resolver.resolve(query.match['depend'].format(**dict(query.genealogy)), query.genealogy, query.context)
            except KeyError as e:
                self.log.debug('failed to assemble remote URL for %s because parameter %s was missing.', query.uri, e)
            else:
                if dependee is not None:
                    query.discover(dependee.genealogy)
                    resolved = True

        if resolved or query.result is not None:
            query.sources.append(Ontology.clone(query.genealogy))

    def parse(self, query):
        for source in query.sources:
            entry = {
                'branch':query.branch,
                'record': Document(self.env, query.branch['namespace'], {
                    'head': {
                        'genealogy': query.genealogy.project('ns/service/genealogy')
                    }
                })
            }
            query.add_entry(entry)
