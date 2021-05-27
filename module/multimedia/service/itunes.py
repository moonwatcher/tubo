# -*- coding: utf-8 -*-

import json
import os
from service import ResourceHandler
from ontology import Ontology, Document

def satisfies(dictionary, condition):
    return all((k in dictionary and dictionary[k] == v) for k,v in condition.items())

class iTunesHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def parse(self, query):
        for source in query.sources:
            if 'preprocess' in query.branch:
                action = getattr(self, query.branch['preprocess'], None)
                if action is not None:
                    source = action(source)
                else:
                    self.log.warning('Ignoring unknown process function %s', query.branch['process'])

            if not source['resultCount'] > 0:
                self.log.debug('No results found for query %s', query.remote)
            else:
                if query.style == 'lookup':
                    for element in source['results']:
                        for product in query.branch['produce']:
                            if satisfies(element, product['condition']):
                                entry = {
                                    'branch':product['branch'],
                                    'record': Document(self.env, product['branch']['namespace'], {
                                        'head': {
                                            'genealogy': query.genealogy.project('ns/service/genealogy')
                                        },
                                        'original': element,
                                    })
                                }
                                entry['record']['body'].interpret(element, self.name)
                                entry['record']['head']['genealogy'].absorb(entry['record']['body'], query.index)
                                query.add_entry(entry)
                                break

                elif query.style == 'discover':
                    if 'produce' in query.branch:
                        for product in query.branch['produce']:
                            for element in source['results']:
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

    def parse_itunes_genres(self, document):
        def _recursive_parse_itunes_genres(node, parent=None):
            result = []
            if node:
                for key, element in node.items():
                    try:
                        geID = int(key)
                    except ValueError as e:
                        self.log.warning('Invalid genre id %s', key)
                    else:
                        record = dict([(k,v) for k,v in element.items() if not k == 'subgenres'])
                        record['kind']= 'genre'
                        if parent:
                            record['parentGenreId'] = parent
                        result.append(record)
                        
                        if 'subgenres' in element and element['subgenres']:
                            result.extend(_recursive_parse_itunes_genres(element['subgenres'], geID))
            return result

        result = { 'results':_recursive_parse_itunes_genres(document) }
        result['resultCount'] = len(result['results'])
        return result
        

