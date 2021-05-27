# -*- coding: utf-8 -*-

import os
import io
import xmltodict
from io import StringIO

from module.core.service.crawler import CrawlHandler
from ontology import Ontology, Document
from error import *

class IlluminaHandler(CrawlHandler):
    def __init__(self, resolver, node):
        CrawlHandler.__init__(self, resolver, node)

    def crawl(self, query):
        self.log.debug('crawling %s', query.location['path'])
        if query.location['kind'] in [ 'ihsz', 'imsz', 'insz' ]:
            query.sources.append({ 'flowcell': Ontology(self.env, 'ns/knowledge/flowcell') })

        else:
            self.crawl_rta_complete(query)
            self.crawl_run_parameters(query)
            self.crawl_run_info(query)

    def crawl_rta_complete(self, query):
        if query.location['inode type'] == 'directory':
            path = os.path.join(query.location['path'], 'RTAComplete.txt')
            try:
                with io.open(path, 'rb') as f:
                    f.read().decode('utf8')

            except FileNotFoundError:
                raise InvalidResourceError('ignoring incomplete flowcell with missing {}'.format(path))

            except OSError as err:
                raise InvalidResourceError(str(err))

    def crawl_run_parameters(self, query):
        def find_run_parameters_file(base):
            path = os.path.join(base, 'runParameters.xml')
            if not os.path.exists(path):
                path = os.path.join(base, 'RunParameters.xml')
                if not os.path.exists(path):
                    path = None
            return path

        source = Ontology(self.env, 'ns/knowledge/flowcell')
        if query.location['inode type'] == 'directory':
            path = find_run_parameters_file(query.location['path'])
            if path is not None:
                content = None
                try:
                    with io.open(path, 'rb') as f:
                        content = StringIO(f.read().decode('utf8'))
                except IOError as err:
                    raise InvalidResourceError('ignoring corrupt flowcell with missing {}'.format(path))
                else:
                    if content is not None:
                        document = xmltodict.parse(content.getvalue())
                        if 'RunParameters' in document:
                            document = document['RunParameters']

                            # Quirks...
                            # move items out of the Setup wrapper, if they are in it.
                            if 'Setup' in document:
                                for k,v in document['Setup'].items():
                                    document[k] = v
                                del document['Setup']

                            # NextSeq
                            if query.location['kind'] == 'inrf':
                                pass

                            # MiSeq
                            if query.location['kind'] == 'imrf':
                                if 'Reads' in document:
                                    del document['Reads']

                            # HiSeq
                            elif query.location['kind'] == 'ihrf':
                                if 'Flowcell' in document:
                                    document['FlowcellType'] = document['Flowcell']
                                    del document['Flowcell']                        

                            source.interpret(document, 'illumina')
                            if 'nibbles' in source:
                                source['nibbles'].sort(key=lambda i: i['nibble number'])
                                source['number of nibbles'] = len(source['nibbles'])
                        else:
                            raise InvalidResourceError('incompatible RunInfo syntax in {}'.format(query.location['path']))
            else:
                raise InvalidResourceError('no run parameters file found in {}'.format(query.location['path']))
        query.sources.append(source)

    def crawl_run_info(self, query):
        source = Ontology(self.env, 'ns/knowledge/flowcell')
        if query.location['inode type'] == 'directory':
            path = os.path.join(query.location['path'], 'RunInfo.xml')
            if path is not None:
                content = None
                try:
                    with io.open(path, 'rb') as f:
                        content = StringIO(f.read().decode('utf8'))
                except IOError as err:
                    raise InvalidResourceError('ignoring corrupt flowcell with missing {}'.format(path))
                else:
                    if content is not None:
                        document = xmltodict.parse(content.getvalue())
                        if 'RunInfo' in document and 'Run' in document['RunInfo']:
                            document = document['RunInfo']['Run']
                            
                            # Quirks...
                            if 'FlowcellLayout' in document:
                                for k,v in document['FlowcellLayout'].items(): document[k] = v
                                del document['FlowcellLayout']

                            if 'Reads' in document:
                                document['Reads'] = document['Reads']['Read']
                                if not isinstance(document['Reads'], list):
                                    document['Reads'] = [ document['Reads'] ]

                            source.interpret(document, 'illumina')
                            if 'nibbles' in source:
                                source['nibbles'].sort(key=lambda i: i['nibble number'])
                                source['number of nibbles'] = len(source['nibbles'])
                        else:
                            raise InvalidResourceError('incompatible RunInfo syntax in {}'.format(query.location['path']))
            else:
                raise InvalidResourceError('no run parameters file found in {}'.format(query.location['path']))
        query.genealogy.absorb(source, query.index)
        query.sources.append({ 'flowcell': source })
