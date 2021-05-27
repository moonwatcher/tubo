#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import logging 
from ontology import Ontology
from material import Resource
from command import Command
from queue import Job, Task, Scanner
from queue import ResourceTask, InstructionTask, DocumentTask
from error import *

class ExportSampleSheetJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)
        self.log = logging.getLogger('Bio')

    def load(self):
        Job.load(self)
        if self.ontology['uris']:
            for uri in self.ontology['uris']:
                self.push(ExportSampleSheetTask(self, self.ontology.project('ns/system/task'), uri))

class ExportSampleSheetTask(DocumentTask):
    def __init__(self, job, ontology, uri):
        DocumentTask.__init__(self, job, ontology, uri)
        self.log = logging.getLogger('Bio')

    def export_samplesheet(self):
        template = {
            'flowcell': [
                'flowcell id',
                'illumina flowcell id'
            ],
            'lane': [
                'lane id',
                'lane number'
            ],
            'pool': [
                'pool id'
            ],
            'sample': [
                'sample id',
                'sample percent'
            ],
            'library': [
                'library id',
                'library name',
                'description',
                'library experimental application',
                'fragment size estimation method',
                'mean fragment size',
                'protocol kit name'
            ]
        }        
        head = []
        records = []
        number_of_barcodes = 0

        for block in template.values():
            for field in block:
                head.append(field)

        flowcell = self.document
        if 'lanes' in flowcell['body']:
            for lane in flowcell['body']['lanes']:
                if 'pools' in lane:
                    for pool in lane['pools']:
                        for sample in pool['samples']:
                            record = {}
                            for field in template['flowcell']:
                                if field in flowcell['head']['genealogy']:
                                    record[field] = flowcell['head']['genealogy'][field]
                                elif field in flowcell['body']:
                                    record[field] = flowcell['body'][field]
                            for field in template['lane']:
                                if field in lane:
                                    record[field] = lane[field]
                            for field in template['pool']:
                                if field in pool:
                                    record[field] = pool[field]
                            for field in template['sample']:
                                if field in sample:
                                    record[field] = sample[field]
                            for field in template['library']:
                                if field in sample['library']:
                                    record[field] = sample['library'][field]
                            if 'barcodes' in sample['library']:
                                number_of_barcodes = max(number_of_barcodes, len(sample['library']['barcodes']))
                                record['barcodes'] = []
                                for barcode in sample['library']['barcodes']:
                                    b = {}
                                    if 'barcode id' in barcode: b['barcode id'] = barcode['barcode id']
                                    if 'barcode nibble' in barcode: b['barcode nibble'] = barcode['barcode nibble']
                                    if 'barcode cycle offset' in barcode: b['barcode cycle offset'] = barcode['barcode cycle offset']
                                    if 'barcode sequence' in barcode: b['barcode sequence'] = barcode['barcode sequence']
                                    record['barcodes'].append(b)
                            records.append(record)

        # remove fields that have no values
        head = [field for field in head if any([field in record for record in records])]

        head.extend(['barcode'] * number_of_barcodes)
        print(','.join(head))
        for record in records:
            t = []
            for field in head:
                if field != 'barcode':
                    t.append('' if field not in record else record[field])

            for index in range(number_of_barcodes):
                if 'barcodes' in record:
                    if index < len(record['barcodes']):
                        barcode = record['barcodes'][index]
                        t.append(
                            '{}:{}:{}:{}'.format(
                                '' if 'barcode id' not in barcode else barcode['barcode id'],
                                '' if 'barcode nibble' not in barcode else barcode['barcode nibble'],
                                '' if 'barcode cycle offset' not in barcode else barcode['barcode cycle offset'],
                                '' if 'barcode sequence' not in barcode else barcode['barcode sequence']
                            )
                        )
                    else: t.append('')
                else: t.extend([''] * number_of_barcodes)
            print(', '.join([str(x) for x in t]))

class ImportSampleSheetJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)
        self.log = logging.getLogger('Bio')

    def load(self):
        Job.load(self)
        for path in self.ontology['scan path']:
            self.push(ImportSampleSheetTask(self, self.ontology.project('ns/system/task'), path))

class ImportSampleSheetTask(InstructionTask):
    def __init__(self, job, ontology, path):
        InstructionTask.__init__(self, job, ontology, path)
        self.log = logging.getLogger('Bio')

    def import_samplesheet(self):
        def convert_csv_to_dictionary():
            document = []
            with io.open(self.instruction['path'], 'r') as f:
                content = f.read().splitlines()
                table = [[field.strip() for field in row.split(',')] for row in  content]
                head = table[0]
                table = table[1:]

                # check that all rows have a tuple no longer than the head
                for index, row in enumerate(table):
                    if len(row) > len(head):
                        raise ValidationError('to many tokens {} instead of at most {} on line {}'.format(len(row), len(head), index))

                for row in table:
                    o = Ontology(self.env, 'ns/instruction/csv/library', { 'barcodes': [] })
                    for index,value in enumerate(row):
                        name = head[index]
                        if name != 'barcode':
                            o.decode(name, value, 'csv')
                        else:
                            if value:
                                parsed = value.split(':')
                                if len(parsed) in [1, 4]:
                                    try:
                                        o['barcodes'].append(Ontology(self.env, 'ns/knowledge/barcode', { 
                                            'barcode id': int(parsed[0])
                                        }))
                                    except ValueError as error:
                                        raise ValidationError('barcode id is not a valid integer {} on line {}'.format(parsed[0] , index))

                                elif len(parsed) == 3:
                                    try:
                                        o['barcodes'].append(Ontology(self.env, 'ns/knowledge/barcode', {
                                            'barcode nibble': int(parsed[0]),
                                            'barcode cycle offset': int(parsed[1]),
                                            'barcode sequence': int(parsed[2])
                                        }))
                                    except ValueError as error:
                                        raise ValidationError('invalid barcode template {} on line {}'.format(value, index))
                                else:
                                    raise ValidationError('invalid barcode template {} on line {}'.format(value, index))
                    document.append(o)
            return document

        def expand_references(buffer):
            for record in buffer['local/flowcell/lanes']:
                record['body']['lanes'] = [Ontology(self.env, 'ns/knowledge/lane', {'lane uuid': uuid}) for uuid in record['body']['lanes']]

            for record in buffer['local/lane/pools']:
                record['body']['pools'] = [Ontology(self.env, 'ns/knowledge/pool', {'pool uuid': uuid}) for uuid in record['body']['pools']]

            for record in buffer['local/library/barcodes']:
                record['body']['barcodes'] = [Ontology(self.env, 'ns/knowledge/barcode', {'barcode uuid': uuid}) for uuid in record['body']['barcodes']]

        def fetch(uri, location, record, table, namespace, index):            
            proxy = None

            if table not in buffer:
                buffer[table] = []

            if uri in lookup:
                proxy = lookup[uri]
            else:
                home = self.env.resolver.resolve(uri, None, self.context)
                if home is not None:

                    # verify there are no contradictions between what is supplied and what is known
                    for word in location:
                        if word in home['head']['genealogy'] and location[word] != home['head']['genealogy'][word]:
                            raise ValidationError('{} {} provided is inconsistent with existing {} for line {}'.format(word, location[word], home['head']['genealogy'][word], index))

                    # project into a native entity
                    o = home['head']['genealogy'].project(namespace)

                    # resolve the local document and decode a body
                    local = self.env.resolver.resolve(o['local uri'], location)
                    local['body'] = record.project(local.namespace)

                    # construct a proxy and add it to the lookup
                    proxy = { 'home': home, 'local': local }
                    buffer[table].append(local)

                    # index the proxy on every alternate uri
                    for alt in home['head']['alternate']:
                        lookup[alt] = proxy

                    # entity specific initialization 
                    if table == 'local/flowcell':
                        proxy['lanes'] = self.env.resolver.resolve(o['flowcell lanes local uri'], location)
                        buffer['local/flowcell/lanes'].append(proxy['lanes'])
                        proxy['lanes']['body']['lanes'] = set()

                    elif table == 'local/lane':
                        proxy['pools'] = self.env.resolver.resolve(o['lane pools local uri'], location)
                        buffer['local/lane/pools'].append(proxy['pools'])
                        proxy['pools']['body']['pools'] = set()
                        proxy['default pool'] = str(uuid.uuid4())

                    elif table == 'local/pool':
                        proxy['samples'] = self.env.resolver.resolve(o['pool samples local uri'], location)
                        buffer['local/pool/samples'].append(proxy['samples'])
                        proxy['samples']['body']['samples'] = []

                    elif table == 'local/sample':
                        del local['body']['library']

                    elif table == 'local/library':
                        del local['body']['barcodes']
                        proxy['barcodes'] = self.env.resolver.resolve(o['library barcodes local uri'], location)
                        buffer['local/library/barcodes'].append(proxy['barcodes'])
                        proxy['barcodes']['body']['barcodes'] = set()
                else:
                    raise ValidationError('could not resolve {} for line {}'.format(uri, index))

            return proxy

        def save(buffer):
            for table in buffer.values():
                for record in table:
                    self.env.resolver.save(record)

        buffer = {
            'local/flowcell': [],
            'local/flowcell/lanes': [],
            'local/lane': [],
            'local/lane/pools': [],
            'local/pool': [],
            'local/pool/samples': [],
            'local/sample': [],
            'local/library': [],
            'local/library/barcodes': [],
            'local/barcode': [],
        }
        lookup = {}
        document = convert_csv_to_dictionary()

        for index, record in enumerate(document):
            location = record.project('ns/service/genealogy')
            if record['flowcell home uri']:
                flowcell = fetch(record['flowcell home uri'], location, record, 'local/flowcell', 'ns/knowledge/flowcell', index)

                if record['lane home uri']:
                    lane = fetch(record['lane home uri'], location, record, 'local/lane', 'ns/knowledge/lane', index)
                    flowcell['lanes']['body']['lanes'].add(lane['local']['head']['genealogy']['lane uuid'])

                    if 'pool id' not in record: record['pool uuid'] = lane['default pool']
                    pool = fetch(record['pool home uri'], location, record, 'local/pool', 'ns/knowledge/pool', index)
                    lane['pools']['body']['pools'].add(pool['local']['head']['genealogy']['pool uuid'])

                    if 'sample id' not in record: record['sample uuid'] = str(uuid.uuid4())
                    sample = fetch(record['sample home uri'], location, record, 'local/sample', 'ns/knowledge/sample', index)
                    reference = record.project('ns/knowledge/sample')
                    reference['sample uuid'] = sample['home']['head']['genealogy']['sample uuid']
                    pool['samples']['body']['samples'].append(reference)

                    if 'library id' not in record: record['library uuid'] = str(uuid.uuid4())
                    library = fetch(record['library home uri'], location, record, 'local/library', 'ns/knowledge/library', index)
                    reference = record.project('ns/knowledge/library')
                    reference['library uuid'] = library['home']['head']['genealogy']['library uuid']
                    sample['local']['body']['library'] = reference

                    if 'barcodes' in record:
                        for b in record['barcodes']:
                            l = b.project('ns/service/genealogy')
                            if 'barcode id' not in l:
                                l['barcode uuid'] = str(uuid.uuid4())
                            barcode = fetch(l['barcode home uri'], l, b, 'local/barcode', 'ns/knowledge/barcode', index)
                            library['barcodes']['body']['barcodes'].add(barcode['local']['head']['genealogy']['barcode uuid'])
                else:
                    raise ValidationError('insufficient information to locate lane on line {}'.format(index))
            else:
                raise ValidationError('insufficient information to locate flowcell on line {}'.format(index))

        expand_references(buffer)
        save(buffer)
        print(self.env.to_json(buffer))
