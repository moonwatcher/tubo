# -*- coding: utf-8 -*-

import json
from io import StringIO
from service import ResourceHandler
from ontology import Ontology, Document

class QueueHandler(ResourceHandler):
    def __init__(self, resolver, node):
        ResourceHandler.__init__(self, resolver, node)

    def fetch(self, query):
        if query.uri in self.env.queue.live:
            content = json.dumps(
                self.env.queue.live[query.uri],
                ensure_ascii=False,
                sort_keys=True,
                default=self.env.default_json_handler
            )
            query.sources.append(json.loads(content))
            query.persistent = False

    def parse(self, query):
        for source in query.sources:
            entry = {
                'style': 'transient',
                'branch':query.branch,
                'record': Document(self.env, None, source)
            }
            query.add_entry(entry)
