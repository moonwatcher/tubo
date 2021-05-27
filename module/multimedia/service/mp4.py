# -*- coding: utf-8 -*-

import os
import json
import xmltodict
from io import BytesIO

from module.core.service.crawler import CrawlHandler
from ontology import Ontology, Document
from command import Command
from queue import Scanner
from error import *

class Mp4Handler(CrawlHandler):
    def __init__(self, resolver, node):
        CrawlHandler.__init__(self, resolver, node)

    def preprocess_mediainfo(self, element):
        if isinstance(element, dict):
            if '@type' in element:
                if element['@type'] == 'General':
                    pass
                elif element['@type'] == 'Video':
                    if element['Format'] == 'JPEG':
                        pass
                    else:
                        pass
                elif element['@type'] == 'Audio':
                    pass
                elif element['@type'] == 'Text':
                    if element['Format'] == 'Timed Text':
                        pass
                    elif element['Format'] == 'Apple text':
                        pass

            for k in list(element.keys()):
                if k in [ 'Cover_Data' ]:
                    del element[k]

                elif k in [ 'Actor', 'Director', 'ScreenplayBy', 'Channel_s_', 'ChannelPositions', 'Format_Profile' ]:
                    element[k] = [ v.strip() for v in element[k].split('/') ]

                elif k in [ 'Encoded_Library_Settings']:
                    element[k] = dict([ v.strip().split('=') for v in element[k].split('/') ])

                else:
                    element[k] = self.preprocess_mediainfo(element[k])

        elif isinstance(element, list):
            for index, o in enumerate(element):
                element[index] = self.preprocess_mediainfo(o)

        return element

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
                # print(mediainfo.output)
                content = BytesIO(mediainfo.output.encode('utf8'))
                document = xmltodict.parse(content)
                document = self.preprocess_mediainfo(document)
                if 'Mediainfo' in document and 'File' in document['Mediainfo']:
                    document = document['Mediainfo']['File']
                    print(self.env.to_json(document))
                    for track in document['track']:
                        stream_type = self.env.enumeration['mediainfo stream type'].search(track['@type'])
                        print(stream_type.node['namespace'])
                        stream = Ontology(self.env, stream_type.node['namespace'])
                        stream.interpret(track, 'mediainfo')
                        print(self.env.to_json(stream))



