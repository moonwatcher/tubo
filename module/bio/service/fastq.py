# -*- coding: utf-8 -*-

import os
import json

from module.core.service.crawler import CrawlHandler
from ontology import Ontology, Document
from command import Command
from queue import Scanner
from error import *

class FastqHandler(CrawlHandler):
    def __init__(self, resolver, node):
        CrawlHandler.__init__(self, resolver, node)

    def crawl(self, query):
        self.log.debug('crawling %s', query.location['path'])
        pheniqs = Command('pheniqs quality', query.context)
        pheniqs.ontology['pheniqs input'] = [ query.location['path'] ]
        pheniqs.execute()
        if pheniqs.returncode == 0 and pheniqs.output is not None:
            if pheniqs.output:
                content = json.loads(pheniqs.output)
                if 'fastq quality reports' in content and content['fastq quality reports']:
                    report = content['fastq quality reports'][0]
                    if 'path' in report: del report['path']
                    source = Ontology(self.env, query.branch['namespace'], { 'fastq quality report': report })
                    query.genealogy.absorb(source, query.index)
                    query.sources.append(source)

