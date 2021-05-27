# -*- coding: utf-8 -*-

import os
from service import ResourceHandler
from ontology import Ontology, Document
from queue import Scanner
from error import *

# Generic crawling handler
# implementing classes should override the crawl function
class CrawlHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        if query.location is None and query.result is not None:
            query.location = query.result.genealogy.project('ns/service/genealogy')

        if query.location and self.env.expand_home_id(query.location):
            if not os.path.islink(query.location['path']):
                try:
                    self.crawl(query)
                except InvalidResourceError as error:
                    self.log.error(str(error))
                    query.sources.clear()
            else:
                # when crawling a symlink instead crawl the target of the symlink and copy the result
                # this can potentially recurse if the symlink target is a symlink itself
                target = os.path.abspath(os.readlink(query.location['path']))
                scanner = Scanner(self.env, Ontology(self.env, 'ns/system/scanner', { 'scan path': [ target ] }))
                for location in scanner.results:
                    reference = self.env.resolver.resolve(location['resource uri'], location, query.context)
                    query.sources.append(reference.body)
                    break

    def parse(self, query):
        if query.sources:
            entry = {
                'branch':query.branch,
                'record': Document(self.env, query.branch['namespace'], {
                    'head': {
                        'genealogy': query.location.project('ns/service/genealogy')
                    }
                })
            }
            for source in query.sources:
                entry['record'].body.overlay(source)
            entry['record'].genealogy.absorb(query.genealogy, query.index)
            entry['record'].genealogy['path digest']
            query.add_entry(entry)

    def crawl(self, query):
        # crawl stub should be implemented by inheriting classes 
        self.log.debug('crawling %s', query.location['path'])

