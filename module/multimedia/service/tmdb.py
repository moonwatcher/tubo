# -*- coding: utf-8 -*-

import json
import os
from service import ResourceHandler
from ontology import Ontology, Document

class TMDbHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def parse(self, query):
        for source in query.sources:
            if 'preprocess' in query.branch:
                action = getattr(self, query.branch['preprocess'], None)
                if action is not None:
                    source = action(query, source)
                else:
                    self.log.warning('Ignoring unknown process function %s', query.branch['process'])
            if query.style == 'lookup':
                entry = {
                    'branch':query.branch,
                    'record': Document(self.env, query.branch['namespace'], {
                        'head': {
                            'genealogy': query.genealogy.project('ns/service/genealogy')
                        },
                        'original': source
                    })
                }
                entry['record'].body.interpret(source, self.name)
                entry['record'].genealogy.absorb(entry['record'].body, query.index)
                query.add_entry(entry)

            elif query.style == 'discover':
                if 'produce' in query.branch:
                    for product in query.branch['produce']:
                        for element in source[query.branch['container']]:
                            if 'condition' not in product or satisfies(element, product['condition']):
                                entry = {
                                    'branch':product['branch'],
                                    'product': product,
                                    'style': product['style'],
                                    'record': Document(self.env, product['branch']['namespace'], {
                                        'head': {
                                            'genealogy': query.genealogy.project('ns/service/genealogy')
                                        },
                                        'original': element,
                                    })
                                }
                                entry['record'].body.interpret(element, self.name)
                                entry['record'].genealogy.absorb(entry['record'].body, query.index)
                                query.add_entry(entry)

    def resolve_media_kind(self, query, document):
        def resolve_media_kind_for_reference(node):
            if 'media_type' in node and 'id' in node:
                if node['media_type'] == 'movie':
                    node['media_kind'] = 9
                    node['movie_id'] = node['id']
                    
                elif node['media_type'] == 'tv':
                    node['media_kind'] = 10
                    node['tv_show_id'] = node['id']
                    
                del node['media_type']
                del node['id']

        if 'cast' in document:
            for element in document['cast']:
                resolve_media_kind_for_reference(element)
                
        if 'crew' in document:
            for element in document['crew']:
                resolve_media_kind_for_reference(element)
        return document

    def expand_tv_season(self, query, document):
        if 'seasons' in document:
            for e in document['seasons']:
                e['tv_show_id'] = document['id']
        return document

    def expand_tv_episode(self, query, document):
        if 'episodes' in document:
            for e in document['episodes']:
                e['tv_show_id'] = query.genealogy['tmdb tv show id']
        return document


