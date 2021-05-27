# -*- coding: utf-8 -*-

import json
from service import ResourceHandler
from ontology import Ontology, Document

class LocalHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        o = Ontology(self.env, query.branch['namespace'])
        # potentially decide eligibility 
        query.sources.append(o)

    def parse(self, query):
        for source in query.sources:
            entry = {
                'branch':query.branch,
                'record': Document(self.env, query.branch['namespace'], {
                    'head': {
                        'genealogy': query.genealogy.project('ns/service/genealogy')
                    },
                    'body': source
                })
            }
            entry['record'].genealogy.absorb(query.location, query.index)
            query.add_entry(entry)
