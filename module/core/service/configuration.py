# -*- coding: utf-8 -*-

import copy
from service import ResourceHandler
from ontology import Ontology, Document

class ConfigurationHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        if 'configuration handle' in query.genealogy:
            section = query.genealogy['configuration handle'] 
            if section in self.env.configuration.state:
                content = { section: copy.deepcopy(self.env.configuration.state[section]) }
                query.sources.append(content)

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
            query.add_entry(entry)
