# -*- coding: utf-8 -*-

from service import ResourceHandler
from ontology import Ontology, Document

class KnowledgeBaseHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        if 'depend' in query.match:
            query.genealogy['language']
            try:
                dependee = self.resolver.resolve(query.match['depend'].format(**dict(query.genealogy)), None, query.context)
            except KeyError as e:
                self.log.debug('failed to assemble remote URL for %s because parameter %s was missing.', query.uri, e)
            else:
                if dependee is not None:
                    query.discover(dependee.genealogy)
                    if 'aggregate' in query.branch:
                        for reference in query.branch['aggregate']:
                            try:
                                related = self.resolver.resolve(reference['uri'].format(**dict(query.genealogy)), None, query.context)
                            except KeyError as e:
                                # self.log.debug('could not create referenced uri for pattern %s because parameter %s was missing', reference['uri'], e)
                                pass
                            else:
                                if related is not None:
                                    query.sources.append(related.body)

    def parse(self, query):
        if query.sources:
            entry = {
                'branch':query.branch,
                'record': Document(self.env, query.branch['namespace'], {
                    'head': {
                        'genealogy': query.genealogy.project('ns/service/genealogy')
                    },
                })
            }
            for source in query.sources:
                self.expand_home(source, query.context)
                entry['record'].body.overlay(source)
            self.expand_knowledge(entry['record'].body, query.context)
            query.add_entry(entry)

    def expand_home(self, document, context):
        def discover(discovered, o):
            for k,v in o.items():
                prototype = o.namespace.find(k)
                if prototype and prototype.type == 'object':
                    discovered.append({ 'prototype':prototype, 'ontology':o[k] })

        if document:
            discovered = []
            discover(discovered, document)
            while discovered:
                node = discovered.pop(0)
                if node['prototype'].plural:
                    for o in node['ontology']:
                        self.env.expand_home(o)
                        discover(discovered, o)
                else:
                    self.env.expand_home(node['ontology'])
                    discover(discovered, node['ontology'])

    def expand_knowledge(self, document, context):
        def discover(discovered, o):
            for k,v in o.items():
                prototype = o.namespace.find(k)
                if prototype and prototype.type == 'object':
                    discovered.append({ 'prototype':prototype, 'ontology':o[k] })

        discovered = []
        discover(discovered, document)
        while discovered:
            node = discovered.pop(0)
            if node['prototype'].plural:
                for o in node['ontology']:
                    self.env.expand_knowledge(o, context)
                    discover(discovered, o)
            else:
                self.env.expand_knowledge(node['ontology'], context)
                discover(discovered, node['ontology'])
