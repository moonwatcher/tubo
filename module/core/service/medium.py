# -*- coding: utf-8 -*-

from service import ResourceHandler
from ontology import Ontology, Document

class MediumHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        if query.branch['name'] == 'service/medium/asset':
            collection = self.repository.database['medium_resource']
            cursor = collection.find({ 'head.genealogy.home id': query.genealogy['home id'] })
            for resource in cursor:
                reference = Document(self.env, None, resource)
                query.sources.append(reference.head)

    def parse(self, query):
        if query.sources:
            entry = {
                'branch':query.branch,
                'record': Document(self.env, query.branch['namespace'], {
                    'head': {
                        'genealogy': query.genealogy.project('ns/service/genealogy')
                    },
                    'body': { 'references': [] },
                })
            }
            for source in query.sources:
                entry['record'].body['references'].append(source)
            entry['record'].body['references'].sort(key=lambda x: x['genealogy']['path'])
            query.add_entry(entry)
