# -*- coding: utf-8 -*-

import json
from service import ResourceHandler
from ontology import Ontology, Document

class WebHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def parse(self, query):
        if query.style == 'lookup':
            for source in query.sources:
                entry = {
                    'branch':query.branch,
                    'record': Document(self.env, query.branch['namespace'], {
                        'head': {
                            'genealogy': query.genealogy.project('ns/service/genealogy')
                        },
                        'original': source,
                    })
                }
                entry['record'].body.interpret(source, self.name)
                entry['record'].genealogy.absorb(entry['record'].body, query.index)
                query.add_entry(entry)
