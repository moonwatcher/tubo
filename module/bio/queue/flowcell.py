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

class FlowcellJob(Job):
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
            for location in scanner.results:
                if location['media kind'] == 50:
                    if (location['inode type'] == 'directory' and location['kind'] in [ 'ihrf', 'imrf', 'inrf' ]):
                        if self.action == 'basecall':
                            if 'lane count' in location:
                                if self.ontology['basecall implementation'] == 'picard':
                                    for index in range(location['lane count']):
                                        lane = Ontology.clone(location)
                                        lane['lane number'] = index + 1
                                        self.push(BasecallTask(self, self.ontology, lane))
                                        count += 1
                                elif self.ontology['basecall implementation'] == 'bcl2fastq':
                                    self.push(BasecallTask(self, self.ontology, location))
                                    count += 1
                            else:
                                # for now we use the presence of lane count as a signal that the rule to identify the 
                                # flowcell model has been triggered. If lane count is missing report an error about the 
                                # illumina flowcell possibly being novel.
                                self.log.error('potentially unknown illumina flowcell model %s', location['illumina flowcell id'])

                        elif self.action in ['sav', 'implode']:
                            self.push(FlowcellTask(self, self.ontology, location))
                            count += 1

                    elif (location['inode type'] == 'file' and location['kind'] in [ 'ihrz', 'imrz', 'inrz' ]):
                        if self.action in [ 'explode' ]:
                            self.push(FlowcellTask(self, self.ontology, location))
                            count += 1

            self.log.debug('%d %s tasks queued in job %s', count, self.action, self.uuid)

class FlowcellTask(ResourceTask):
    def __init__(self, job, ontology, location):
        ResourceTask.__init__(self, job, ontology, location)
        self.log = logging.getLogger('Bio')

    def extract_interop(self):
        def find_run_parameters_file(base):
            path = os.path.join(base, 'runParameters.xml')
            if not os.path.exists(path):
                path = os.path.join(base, 'RunParameters.xml')
                if not os.path.exists(path):
                    path = None
            return path

        if self.resource.node is not None:
            tar = Command('tar', self.context, self.ontology)
            rsync = Command('rsync', self.context)
            if tar.valid:
                if rsync.valid:
                    objective = os.path.join(tar.ontology['work directory'], self.resource.location['illumina flowcell id'])
                    try:
                        self.env.prepare_directory(objective)
                    except (NoOverwriteError, PermissionDeniedError) as e:
                        self.abort(str(e))
                    else:
                        interop_path = os.path.join(self.resource.path, 'InterOp')
                        rsync.ontology['recursive rsync'] = True
                        rsync.ontology['positional'] = [ 
                            interop_path,
                            os.path.join(self.resource.path, 'RunInfo.xml'),
                            find_run_parameters_file(self.resource.path),
                            objective
                        ]
                        rsync.execute()

                        override = {
                            'extension': 'tar',
                            'inode type': 'file',
                            'compression': tar.ontology['compression']
                        }
                        if self.resource.location['kind'] == 'ihrf':
                            override['kind'] = 'ihsz'
                        elif self.resource.location['kind'] == 'inrf':
                            override['kind'] = 'insz'
                        elif self.resource.location['kind'] == 'imrf':
                            override['kind'] = 'imsz'
                        product = self.produce(self.resource.origin, override)
                        try:
                            self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
                        except (NoOverwriteError, PermissionDeniedError) as e:
                            self.abort(str(e))
                        else:
                            tar.cwd = tar.ontology['work directory']
                            tar.ontology['tar create'] = True
                            tar.ontology['tar file'] = product.path
                            tar.ontology['positional'] = [ self.resource.location['illumina flowcell id'] ]
                            self.log.debug('compress {} --> {}'.format(self.resource.location['illumina flowcell id'], product.path))
                            tar.execute()
                else:
                    self.abort('command {} is invalid'.format(rsync.name))
            else:
                self.abort('command {} is invalid'.format(tar.name))

    def tar_flowcell(self):
        if self.resource.node is not None:
            if (self.resource.location['media kind'] == 50 and 
                self.resource.location['inode type'] == 'directory'):

                tar = Command('tar', self.context, self.ontology)
                if tar.valid:
                    override = { 'extension': 'tar', 'inode type': 'file', 'compression': tar.ontology['compression'] }
                    if self.resource.location['kind'] == 'ihrf': override['kind'] = 'ihrz'
                    elif self.resource.location['kind'] == 'imrf': override['kind'] = 'imrz'
                    elif self.resource.location['kind'] == 'inrf': override['kind'] = 'inrz'

                    product = self.produce(self.resource.origin, override)
                    try:
                        self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
                    except (NoOverwriteError, PermissionDeniedError) as e:
                        self.abort(str(e))
                    else:
                        tar.cwd = self.resource.location['dirname']
                        tar.ontology['tar create'] = True
                        tar.ontology['tar file'] = product.path
                        tar.ontology['positional'] = [ self.resource.location['basename'] ]
                        self.log.debug('compress {} --> {}'.format(self.resource.path, product.path))
                        tar.execute()
                else:
                    self.abort('command {} is invalid'.format(tar.name))
            else:
                self.abort('only compressing flowcell run directory supported')
        else:
            self.abort('could not crawl resource metadata')

    def untar_flowcell(self):
        if self.resource.node is not None:
            if (self.resource.location['media kind'] == 50 and 
                self.resource.location['inode type'] == 'file' and 
                self.resource.location['extension'] == 'tar'):

                tar = Command('tar', self.context, self.ontology)
                if 'compression' not in self.ontology:
                    tar.ontology['compression'] = self.resource.location['compression']

                if tar.valid:
                    override = { 'extension': None, 'compression': None, 'inode type': 'directory' }
                    if self.resource.location['kind'] == 'ihrz':
                        override['kind'] = 'ihrf'
                    elif self.resource.location['kind'] == 'imrz':
                        override['kind'] = 'imrf'
                    elif self.resource.location['kind'] == 'inrz':
                        override['kind'] = 'inrf'
                    product = self.produce(self.resource.origin, override)
                    try:
                        self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
                    except (NoOverwriteError, PermissionDeniedError) as e:
                        self.abort(str(e))
                    else:
                        tar.cwd = product.location['dirname']
                        tar.ontology['tar extract'] = True
                        tar.ontology['tar file'] = self.resource.path
                        self.log.debug('uncompress {} --> {}'.format(self.resource.path, product.location['dirname']))
                        tar.execute()
                else:
                    self.abort('command {} is invalid'.format(tar.name))
            else:
                self.abort('only uncompressing flowcell run directory archive supported')
        else:
            self.abort('could not crawl resource metadata')

class BasecallTask(ResourceTask):
    def __init__(self, job, ontology, location):
        ResourceTask.__init__(self, job, ontology, location)
        self.log = logging.getLogger('Bio')
        if self.valid:
            if self.ontology['basecall implementation'] == 'picard':
                self.ontology['task cores'] = self.env.constant['picard threads per lane']

            elif self.ontology['basecall implementation'] == 'bcl2fastq':
                if 'lane count' in self.location:
                   self.ontology['task cores'] = self.location['lane count'] * self.env.constant['bcl2fastq threads per lane']

    def basecall(self):
        if self.ontology['basecall implementation'] == 'picard':
            self.picard_basecall()

        elif self.ontology['basecall implementation'] == 'bcl2fastq':
            self.bcl2fastq_basecall()

    def picard_basecall(self):
        if self.resource.node is not None:
            picard = Command('picard illuminabasecallstofastq', self.context, self.resource.location)
            picard.ontology.overlay(self.ontology)
            if picard.valid:
                flowcell = self.resource.node['body']['flowcell']
                picard.ontology['picard read structure'] = ''.join([ '{}T'.format(n['nibble cycle count']) for n in flowcell['nibbles'] ])
                try:
                    self.env.prepare_directory(picard.ontology['picard temp directory'])
                except (NoOverwriteError, PermissionDeniedError) as e:
                    self.abort(str(e))
                else:
                    self.log.debug('basecalling with picard IlluminaBasecallsToFastq to {}'.format(picard.ontology['work directory']))
                    picard.execute()

                    if self.valid:
                        # Scan for FASTQ products
                        scanner = Scanner(self.env, 
                            Ontology(self.env, 'ns/system/scanner',
                                {
                                    'recursive': True,
                                    'filter': [ r'+ \.fastq\.gz', r'- \.*' ],
                                    'scan path': [ picard.ontology['work directory'] ]
                                }
                            )   
                        )

                        # Queue tasks to move the FASTQ products to the repository
                        for location in scanner.results:
                            o = self.job.ontology.project('ns/system/task')
                            o['action'] = 'move'
                            t = ResourceTask(self.job, o, location)
                            t.group = self.uuid
                            t.constrain(
                                {
                                    'condition scope': 'task',
                                    'task status': 'pending',
                                    'task reference': self.uuid,
                                    'task reference status': 'completed',
                                    'task status to apply': 'ready'
                                }
                            )

                            t.constrain(
                                {
                                    'condition scope': 'task',
                                    'task status': 'pending',
                                    'task reference': self.uuid,
                                    'task reference status': 'aborted',
                                    'task status to apply': 'aborted'
                                }
                            )
                            self.job.push(t)
            else:
                self.abort('command {} is invalid'.format(picard.name))
        else:
            self.abort('could not crawl resource metadata')

    def bcl2fastq_basecall(self):
        if self.resource.node is not None:
            if (self.resource.location['kind'] in [ 'ihrf', 'imrf' ]):
                bcl2fastq = Command('bcl2fastq', self.context, self.resource.location)
                if bcl2fastq.valid:
                    flowcell = self.resource.node['body']['flowcell']
                    expected = []
                    # infer the base mask for a pure bcl to fastq conversion
                    # we decalre all nibbles as reads with 'Y' so that each gets written, completely, to a separate fastq file 
                    bcl2fastq.ontology['bcl2fastq use bases mask'] = ','.join([ 'Y{}'.format(n['nibble cycle count']) for n in flowcell['nibbles'] ])

                    try:
                        self.env.prepare_to_write_to_path(bcl2fastq.ontology['bcl2fastq output dir'], self.ontology['overwrite'])
                        self.env.prepare_to_write_to_path(bcl2fastq.ontology['bcl2fastq sample sheet'], self.ontology['overwrite'])
                    except (NoOverwriteError, PermissionDeniedError) as e:
                        self.abort(str(e))
                    else:
                        # Create a sample sheet csv file for pure bcl to fastq conversion
                        self.log.debug('write samplesheet {}'.format(bcl2fastq.ontology['bcl2fastq sample sheet']))
                        content = [ self.env.constant['bcl2fastq samplesheet header'] ]
                        for index in range(bcl2fastq.ontology['lane count']):
                            lane_number = index + 1
                            control = 'Y' if ('control lane number' in flowcell and lane_number == flowcell['control lane number']) else 'N'
                            content.append('{0},{1},{0},,Undetermined,,{2},,,lane{1}'.format(bcl2fastq.ontology['illumina flowcell id'], lane_number, control))
                            for n in range(flowcell['number of nibbles']):
                                nibble_number = n + 1
                                product = self.produce(self.resource.origin,
                                    {
                                        'lane number': lane_number, 
                                        'nibble number': nibble_number,
                                        'media kind': 51,
                                        'extension': 'fastq',
                                        'kind': 'fastq',
                                        'compression': 'gz',
                                        'inode type': 'file'
                                    }
                                )
                                self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
                                expected.append(product)
                        try:
                            with io.open(bcl2fastq.ontology['bcl2fastq sample sheet'], 'wb') as w:
                                w.write('\n'.join(content).encode('utf8'))                    
                        except OSError as error:
                            self.abort('writing samplesheet file to {} failed'.format(bcl2fastq.ontology['bcl2fastq sample sheet']))
                            self.log.error(str(error))

                        if self.valid:
                            self.log.debug('configure BCL to FASTQ {}'.format(bcl2fastq.ontology['work directory']))
                            bcl2fastq.execute()
                else:
                    self.abort('command {} is invalid'.format(bcl2fastq.name))

                if self.valid:
                    make = Command('bcl2fastq make', self.context)
                    if make.valid:
                        # Potentially override values provided by the task on the command line
                        make.ontology.overlay(self.ontology)
                        make.cwd = bcl2fastq.ontology['bcl2fastq output dir']
                        self.log.debug('convert BCL to FASTQ {}'.format(bcl2fastq.ontology['work directory']))
                        make.execute()
                    else:
                        self.abort('command {} is invalid'.format(make.name))

                if self.valid:
                    # Scan for FASTQ products
                    scanner = Scanner(self.env, 
                        Ontology(self.env, 'ns/system/scanner',
                            {
                                'recursive': True,
                                'filter': [ r'+ \.fastq\.gz', r'- \.*' ],
                                'scan path': [ bcl2fastq.ontology['bcl2fastq output dir'] ]
                            }
                        )   
                    )

                    # Queue tasks to move the FASTQ products to the repository
                    for location in scanner.results:
                        o = self.job.ontology.project('ns/system/task')
                        o['action'] = 'move'
                        t = ResourceTask(self.job, o, location)
                        t.group = self.uuid
                        t.constrain(
                            {
                                'condition scope': 'task',
                                'task status': 'pending',
                                'task reference': self.uuid,
                                'task reference status': 'completed',
                                'task status to apply': 'ready'
                            }
                        )

                        t.constrain(
                            {
                                'condition scope': 'task',
                                'task status': 'pending',
                                'task reference': self.uuid,
                                'task reference status': 'aborted',
                                'task status to apply': 'aborted'
                            }
                        )
                        self.job.push(t)
            else:
                self.abort('{} not implemented with for bcl2fastq'.format(self.resource.location['kind']))
        else:
            self.abort('could not crawl resource metadata')

