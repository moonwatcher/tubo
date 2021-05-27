# -*- coding: utf-8 -*-

import json
from service import ResourceHandler
from ontology import Ontology, Document


class RottenTomatoesHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def parse(self, query):
        for source in query.sources:
            if 'error' in source:
                self.log.warning('Rotten tomatoes api error for %s: %s', query['remote url'], source['error'])
            else:
                entry = {
                    'branch':query.branch,
                    'record': Document(self.env, query.branch['namespace'], {
                        'head': {
                            'genealogy': query.genealogy.project('ns/service/genealogy'),
                        },
                        'original': source
                    })
                }

                # Rotten tomatoes specific overrides
                if entry['branch']['name'] == '/service/document/rottentomatoes/movie':
                    # Rotten tomatoes holds the imdb id without the tt prefix, inside the alternate_ids dictionary
                    if 'alternate_ids' in source and 'imdb' in source['alternate_ids'] and source['alternate_ids']['imdb']:
                        source['imdb_id'] = 'tt{0}'.format(source['alternate_ids']['imdb'])

                    # Flatten the release date
                    if 'release_dates' in source and 'theater' in source['release_dates']:
                        source['release_date'] = source['release_dates']['theater']

                if entry['branch']['name'] == 'service/document/rottentomatoes/movie/review' and 'reviews' in source:
                    # Flatten the review links
                    for r in source['reviews']:
                        if 'links' in r and 'review' in r['links']: r['review_link'] = r['links']['review']

                entry['record'].body.interpret(source, self.name)

                # Movie ratings are stored in a sub container, simply decode them directly from there
                if entry['branch']['name'] == 'service/document/rottentomatoes/movie':
                    if 'ratings' in source:
                        entry['record'].body.interpret(source['ratings'], self.name)

                entry['record'].genealogy.absorb(entry['record'].body, query.index)
                query.add_entry(entry)

