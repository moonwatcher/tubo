# -*- coding: utf-8 -*-

import os
import json
import xmltodict

from module.core.service.crawler import CrawlHandler
from ontology import Ontology, Document
from command import Command
from queue import Scanner
from error import *

class MatroskaHandler(CrawlHandler):
    def __init__(self, resolver, node):
        CrawlHandler.__init__(self, resolver, node)

    def crawl(self, query):
        self.log.debug('crawling %s', query.location['path'])
        mediainfo = Command('mediainfo', query.context)
        mediainfo.ontology['mediainfo full'] = True
        mediainfo.ontology['mediainfo output'] = 'XML'
        mediainfo.ontology['mediainfo language'] = 'raw'
        mediainfo.ontology['positional'] = [ query.location['path'] ]
        mediainfo.execute()
        if mediainfo.returncode == 0 and mediainfo.output is not None:
            if mediainfo.output:
                document = xmltodict.parse(mediainfo.output.decode('utf8'))
                print(self.env.to_json(document))


