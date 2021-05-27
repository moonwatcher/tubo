#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import json

from queue import Job, Task
from ontology import Ontology
from material import Resource
from command import Command
from error import *

inode_type = lambda path: ( os.path.isfile(path) and 'file' ) or 'directory'

class InstructionJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)

    def load(self):
        Job.load(self)
        for path in self.ontology['scan path']:
            self.push(InstructionTask(self, self.ontology.project('ns/system/task'), path))

class InstructionTask(Task):
    def __init__(self, job, ontology, path):
        Task.__init__(self, job, ontology)
        self.path = path
        self.instruction = None

    def load(self):
        Task.load(self)
        if self.valid:
            path = os.path.abspath(os.path.expanduser(os.path.expandvars(self.path)))
            if os.path.exists(path):
                if os.access(path, os.R_OK):
                    # allocate a new ontology
                    self.instruction = Ontology( self.env, 'ns/instruction/basename/decode',
                        {
                            'path': path,
                            'inode type': inode_type(path),
                            'dirname': os.path.dirname(path),
                            'basename': os.path.basename(path),
                            'work directory': self.node['work directory']
                        }
                    )
                else:
                    raise PermissionDeniedError(path)
            else:
                raise FileNotFoundError(path)

    def restore(self):
        restore = Command('mongorestore', self.context, self.ontology)
        if restore.valid:
            restore.ontology.overlay(self.repository.mongodb)
            tar = Command('tar', self.context, self.ontology)
            if tar.valid:
                tar.ontology['tar file'] = self.path
                tar.ontology['tar extract'] = True
                tar.ontology['compression'] = self.instruction['compression']
                try:
                    self.env.prepare_to_write_to_path(restore.ontology['mongorestore input directory'], self.ontology['overwrite'])
                except (NoOverwriteError, PermissionDeniedError) as e:
                    self.abort(str(e))
                else:
                    self.log.debug('expand archive {}'.format(self.path))
                    tar.execute()
            else:
                self.abort('command {} is invalid'.format(tar.name))

            if self.valid:
                restore.ontology['positional'] = [ restore.ontology['database'] ]
                self.log.debug('restoring from {}'.format(restore.ontology['mongorestore input directory']))
                restore.execute()
        else:
            self.abort('command {} is invalid'.format(restore.name))

    def import_action(self):
        self.instruction['compression']
        mongoimport = Command('mongoimport', self.context, self.ontology)
        if mongoimport.valid:
            mongoimport.ontology.overlay(self.repository.mongodb)
            tar = Command('tar', self.context, self.ontology)
            if tar.valid:
                tar.ontology['tar file'] = self.path
                tar.ontology['tar extract'] = True
                tar.ontology['compression'] = self.instruction['compression']
                try:
                    self.env.prepare_to_write_to_path(mongoimport.ontology['mongoimport input directory'], self.ontology['overwrite'])
                except (NoOverwriteError, PermissionDeniedError) as e:
                    self.abort(str(e))
                else:
                    self.log.debug('expand archive {}'.format(self.path))
                    tar.execute()
            else:
                self.abort('command {} is invalid'.format(tar.name))

            if self.valid:
                for path in os.listdir(mongoimport.ontology['mongoimport input directory']):
                    table, extension = os.path.splitext(path)
                    mongoimport = Command('mongoimport', self.context, self.ontology)
                    mongoimport.ontology.overlay(self.repository.mongodb)
                    mongoimport.cwd = mongoimport.ontology['mongoimport input directory']
                    mongoimport.ontology['mongoimport input path'] = path
                    mongoimport.ontology['mongodb collection'] = table
                    self.log.debug('restoring {} from {}'.format(mongoimport.ontology['mongodb collection'], mongoimport.ontology['mongoimport input path']))
                    mongoimport.execute()
        else:
            self.abort('command {} is invalid'.format(mongoimport.name))
