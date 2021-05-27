#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import logging 

from ontology import Ontology
from material import Resource
from command import Command
from queue import Job, Task, Scanner
from queue import ResourceTask
from error import *

class DemuxJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)
        self.log = logging.getLogger('Bio')

    def load(self):
        Job.load(self)
        scanner = Scanner(self.env, self.ontology)
        if scanner.ignored:
            self.node['ignored'].extend(scanner.ignored)
        if scanner.results:
            count = 0
            if self.action == 'demux':
                # every lane is demultiplxed by a separate task 
                # we break the fastq files into tasks by flowcell/lane
                breakdown = {}
                for location in scanner.results:
                    if 'flowcell id' in location and 'lane number' in location:
                        if location['flowcell id'] not in breakdown:
                            breakdown[location['flowcell id']] = {}
                        if location['lane number'] not in breakdown[location['flowcell id']]:
                            breakdown[location['flowcell id']][location['lane number']] = []
                        breakdown[location['flowcell id']][location['lane number']].append(location)

                for flowcell in breakdown.values():
                    for lane in flowcell.values():
                        self.push(DemuxTask(self, self.ontology, lane))
                        count += 1

            elif self.action == 'merge':
                # merge all files from different lanes but with the same nibble number
                breakdown = {}
                for location in scanner.results:
                    if 'flowcell id' in location and 'nibble number' in location:
                        if location['flowcell id'] not in breakdown:
                            breakdown[location['flowcell id']] = {}
                        if location['nibble number'] not in breakdown[location['flowcell id']]:
                            breakdown[location['flowcell id']][location['nibble number']] = []
                        breakdown[location['flowcell id']][location['nibble number']].append(location)

                for flowcell_id, flowcell in breakdown.items():
                    for nibble_number in flowcell.keys():
                        flowcell[nibble_number] = sorted(flowcell[nibble_number], key=lambda x: x['lane number'])

                    pattern = [':'.join([ str(x['lane number']) for x in nibble ]) for nibble in flowcell.values()]
                    if len(set(pattern)) > 1:
                        self.abort('not all lanes have the same number of nibbles in flowcell {}'.format(flowcell_id))
                    else:
                        for nibble in flowcell.values():
                            self.push(MergeTask(self, self.ontology, nibble))
                            count += 1

            elif self.action == 'filter':
                for location in scanner.results:
                    self.push(FilterTask(self, self.ontology, location))
                    count += 1

            self.log.debug('%d %s tasks queued in job %s', count, self.action, self.uuid)

class DemuxTask(Task):
    def __init__(self, job, ontology, locations):
        Task.__init__(self, job, ontology)
        self.log = logging.getLogger('Bio')
        self.locations = locations
        self.resources = []
        self.flowcell = None
        self.lane = None
        self.template = None
        self.node['origins'] = []

    def load(self):
        Task.load(self)
        def fetch_flowcell_resource(resource):
            # Locate an ihrf, inrf or imrf resource we can use to get meatadata about the flowcell 
            flowcell = None
            asset = self.env.resolver.resolve(resource.location['flowcell asset uri'], None, self.context)
            if asset is not None:
                for reference in asset['body']['references']:
                    if reference['genealogy']['media kind'] == 50 \
                    and (reference['genealogy']['kind'] in [ 'ihrf', 'imrf', 'inrf' ]):
                        flowcell = self.env.resolver.resolve(reference['canonical'], None, self.context)
                        if flowcell is not None:
                            break
            return flowcell

        # Since all resources are assumed to come from the same flowcell
        # pick a representing resource.
        representing = None

        if self.valid:
            for location in self.locations:
                resource = Resource.create(self.env, location, self.context)
                if resource is not None:
                    self.node['origins'].append(location)
                    self.resources.append(resource)
                else:
                    self.abort('resource location is invalid:\n{}'.format(self.env.to_json(location)))

            if self.resources:
                representing = self.resources[0]
            else:
                self.abort('need at least one resource to demultiplex')

        if self.valid:
            self.flowcell = fetch_flowcell_resource(representing)
            if self.flowcell is None:
                self.abort('no suitable flowcell resource found to infer pheniqs output layout')

        if self.valid:
            if 'knowledge uri' in representing.location:
                if representing.knowledge:
                    self.lane = representing.knowledge
                    if 'pools' not in self.lane['body']:
                        self.abort('no pools are associated with lane {}'.format(representing.location['home uri']))
                else:
                    self.abort('was unable to resolve {}'.format(representing.location['knowledge uri']))
            else:
                self.abort('insufficient information to resolve lane from\n{}'.format(self.env.to_json(representing.location)))

        if self.valid:
            self.template = Ontology.clone(representing.location)
            for e in [
                'nibble number',
            ]: del self.template[e]
            self.template['media kind'] = 53

    def unload(self):
        if self.resources:
            if self.valid:
                for resource in self.resources:
                    resource.unload()
        else:
            del self.node['origins']

        Task.unload(self)

    def last_fragment(self, command):
        return len(command.ontology['pheniqs fragment']) - 1

    def write_configuration_file(self, command):
        def encode_pheniqs_config(ontology):
            node = {}
            for prototype in ontology.namespace.element.values():
                if prototype.key in ontology:
                    value = ontology[prototype.key]
                    if value is not None and 'config' in prototype.node:
                        name = prototype.node['config']
                        if prototype.type == 'object':
                            if prototype.plural and value:
                                node[name] = [ encode_pheniqs_config(e) for e in value ]
                            else:
                                node[name] = encode_pheniqs_config(value)
                        elif not prototype.plural or value:
                            node[name] = value
            return node

        node = encode_pheniqs_config(command.ontology)
        with io.open(command.ontology['pheniqs configuration path'], 'wb') as w:
            w.write(self.env.to_json(node).encode('utf8'))

    def reverse_complement(self, nucleotide):
        complement = self.env.enumeration['iupac nucleic acid notation'].element
        reversed = ''.join([ complement[n].node['reverse'] for n in nucleotide ][::-1])
        return reversed

    def configure(self, pheniqs):
        if self.valid:
            for term in [
                'pheniqs barcode',
                'pheniqs fragment',
                'pheniqs input',
                'pheniqs library',
                'pheniqs output',
                'pheniqs sequence'
            ]:
                if term not in pheniqs.ontology:
                    pheniqs.ontology[term] = []

            if not pheniqs.ontology['pheniqs library']:
                if 'nibbles' in self.flowcell['body']['flowcell'] and self.flowcell['body']['flowcell']['nibbles']:
                    # append a new fragment spanning the entire nibble for each non index nibble
                    # than add a library output contaning just that fragment
                    for nibble in self.flowcell['body']['flowcell']['nibbles']:
                        if not nibble['index nibble']:
                            pheniqs.ontology['pheniqs fragment'].append('{}:0:'.format(nibble['nibble number'] - 1))
                            pheniqs.ontology['pheniqs library'].append(str(self.last_fragment(pheniqs)))

                if not pheniqs.ontology['pheniqs library']:
                    self.abort('could not find any non index nibbles to write')

        # Add all task resources as pheniqs inputs
        if self.valid:
            for input in self.resources:
                pheniqs.ontology['pheniqs input'].append(input.path)

        if self.valid:
            for pool in self.lane['body']['pools']:
                if 'pool barcodes' in pool:
                    pool['pool barcodes'].sort(key=lambda i: i['barcode index'])

                if 'samples' in pool:
                    for sample in pool['samples']:
                        if 'library' in sample:
                            library = sample['library']
                            if library['barcodes']:
                                for index,barcode in enumerate(library['barcodes']):
                                    nucleotide = barcode['barcode sequence']

                                    # reverse complement the barcode if needed
                                    if ('pool barcodes' in pool and \
                                        index < len(pool['pool barcodes']) and \
                                        'barcode reverse complement' in pool['pool barcodes'][index] and \
                                        pool['pool barcodes'][index]['barcode reverse complement']):
                                            reversed = self.reverse_complement(nucleotide)
                                            self.log.debug('reverse complementing %s to %s', nucleotide, reversed)
                                            nucleotide = reversed

                                    pheniqs.ontology['pheniqs sequence'].append(nucleotide)

                                # infer an output product for each nibble 
                                for index in range(len(pheniqs.ontology['pheniqs library'])):
                                    if self.valid:
                                        o = Ontology.clone(self.template)
                                        o.overlay(library.project('ns/service/genealogy'))
                                        o.overlay(sample.project('ns/service/genealogy'))
                                        o['nibble number'] = index + 1
                                        product = self.produce(o)
                                        pheniqs.ontology['pheniqs output'].append(product.path)
                            else:
                                self.log.warning('ignoring library %s with missing barcodes', library['home uri'])
                        else:
                            self.log.warning('ignoring sample %s with missing library ', sample['home uri'])

    def validate(self, pheniqs):
        if self.valid:
            pattern = { 'barcode':{} }
            for pool in self.lane['body']['pools']:
                if 'samples' in pool:
                    for sample in pool['samples']:
                        if 'library' in sample:
                            library = sample['library']
                            if library['barcodes']:
                                for index,barcode in enumerate(library['barcodes']):
                                    if index not in pattern['barcode']:
                                        pattern['barcode'][index] = []

                                    pattern['barcode'][index].append(
                                        '{}:{}:{}'.format(
                                            barcode['barcode nibble'] - 1,
                                            barcode['barcode cycle offset'] - 1,
                                            barcode['barcode length']
                                        )
                                    )

            # verify all barcodes in each collection have an identical pattern
            for index,collection in pattern['barcode'].items():
                if len(set(collection)) == 1:
                    pheniqs.ontology['pheniqs fragment'].append(collection[0])
                    pheniqs.ontology['pheniqs barcode'].append(str(self.last_fragment(pheniqs)))
                else:
                    self.abort('barcodes in set {} are heterogeneous: {}'.format(index, ', '.join(collection)))

        if self.valid:
            if pheniqs.ontology['pheniqs output']:
                for path in pheniqs.ontology['pheniqs output']:
                    try:
                        self.env.prepare_to_write_to_path(path, self.ontology['overwrite'])
                    except (NoOverwriteError, PermissionDeniedError) as e:
                        self.abort(str(e))
                        break
            else:
                self.abort('no libraries to demultiplex')

    def pheniqs_demux(self):
        pheniqs = Command('pheniqs demux', self.context)
        if pheniqs.valid:
            try:
                self.env.prepare_to_write_to_path(pheniqs.ontology['pheniqs configuration path'], self.ontology['overwrite'])
            except (NoOverwriteError, PermissionDeniedError) as e:
                self.abort(str(e))
            else:
                self.configure(pheniqs)
                self.validate(pheniqs)
                if self.valid:
                    try:
                        self.write_configuration_file(pheniqs)
                    except OSError as error:
                        self.abort('writing pheniqs configuration file to {} failed'.format(pheniqs.ontology['pheniqs configuration path']))
                        self.log.error(str(error))
                    else:
                        self.log.info('using pheniqs configuration %s', pheniqs.ontology['pheniqs configuration path'])
                        pheniqs.execute()
        else:
            self.abort('command {} is invalid'.format(pheniqs.name))

class FilterTask(ResourceTask):
    def __init__(self, job, ontology, location):
        ResourceTask.__init__(self, job, ontology, location)
        self.log = logging.getLogger('Bio')

    def pheniqs_filter(self):
        product = self.produce(self.resource.origin)
        if self.resource.local and product.local:
            try:
                self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
            except (NoOverwriteError, PermissionDeniedError) as e:
                self.abort(str(e))
            else:
                pheniqs = Command('pheniqs filter', self.context)
                if pheniqs.valid:
                    pheniqs.ontology['pheniqs input'].append(self.resource.qualified_path)
                    pheniqs.ontology['pheniqs output'].append(product.path)
                    self.log.debug('pheniqs filter {} --> {}'.format(self.resource.qualified_path, product.qualified_path))
                    pheniqs.execute()
                else:
                    self.abort('command {} is invalid'.format(rsync.name))
        else:
            self.abort('filter can only be done locally')

class MergeTask(Task):
    def __init__(self, job, ontology, locations):
        Task.__init__(self, job, ontology)
        self.log = logging.getLogger('Bio')
        self.locations = locations
        self.resources = []
        self.node['origins'] = []

    def load(self):
        Task.load(self)
        if self.valid:
            for location in self.locations:
                resource = Resource.create(self.env, location, self.context)
                if resource is not None:
                    self.node['origins'].append(location)
                    self.resources.append(resource)
                else:
                    self.abort('resource location is invalid:\n{}'.format(self.env.to_json(location)))

    def unload(self):
        if self.resources:
            if self.valid:
                for resource in self.resources:
                    resource.unload()
        else:
            del self.node['origins']

        Task.unload(self)

    def merge_fastq(self):
        origin = Ontology.clone(self.resources[0].origin)
        origin['media kind'] = 50
        product = self.produce(origin)
        if product.local:
            try:
                self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
            except (NoOverwriteError, PermissionDeniedError) as e:
                self.abort(str(e))
            else:
                if not self.simulated:
                    with io.open(product.path, 'wb') as o:
                        for resource in self.resources:
                            with io.open(resource.path, 'rb') as i:
                                o.write(i.read())
                else:
                    self.log.info(
                        'merge {} --> {}'.format(
                            ' + '.join([resource.path for resource in self.resources]),
                            product.path
                        )
                    )
        else:
            self.abort('merge can only be done locally')
