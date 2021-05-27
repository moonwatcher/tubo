#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from queue import Job, Task
from ontology import Ontology
from command import Command
from error import *

class TableJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)

    def load(self):
        Job.load(self)

        # no specific table name means all
        if not self.ontology['tables']: self.ontology['all'] = True

        # if the --all flag was specificed operate on all known tables
        if self.ontology['all']:
            self.push(TableTask(self, self.ontology, list(self.env.table.keys())))

        # otherwise, if a table list was specificed, use the list to create the tasks
        elif self.ontology['tables']:
            self.push(TableTask(self, self.ontology, self.ontology['tables']))

class TableTask(Task):
    def __init__(self, job, ontology, names):
        Task.__init__(self, job, ontology)
        self.tables = []

        if names:
            for name in names:
                if name in self.env.table:
                    self.tables.append(self.env.table[name])
                else:
                    self.abort('table {} is unknown'.format(name))
        else:
            self.abort('a table name must be specified')

    def rebuild(self):
        for table in self.tables:
            self.repository.rebuild_indexes(table['key'], self.ontology['drop on restore'])

    def backup(self):
        dump = Command('mongodump', self.context, self.ontology)
        dump.ontology.overlay(self.repository.mongodb)
        if dump.valid:
            try:
                self.env.prepare_to_write_to_path(dump.ontology['mongodump output directory'], self.ontology['overwrite'])
            except (NoOverwriteError, PermissionDeniedError) as e:
                self.abort(str(e))
            else:
                # dump the tables into a staging directory
                for table in self.tables:
                    if self.valid:
                        d = Command('mongodump', self.context, self.ontology)
                        if d.valid:
                            d.ontology.overlay(self.repository.mongodb)
                            d.ontology['mongodb collection'] = table['collection']
                            self.log.debug('dump table {}'.format(table['key']))
                            d.execute()
                        else:
                            self.abort('command {} is invalid'.format(d.name))

                # create a tarball
                if self.valid:
                    tar = Command('tar', self.context, self.ontology)
                    if tar.valid:
                        tar.ontology['dirname'] = self.node['work directory']
                        tar.ontology['archive name'] = self.node['timestamp']
                        try:
                            self.env.prepare_to_write_to_path(tar.ontology['tar file'], self.ontology['overwrite'])
                        except (NoOverwriteError, PermissionDeniedError) as e:
                            self.abort(str(e))
                        else:
                            tar.ontology['tar create'] = True
                            tar.ontology['positional'] = [ dump.ontology['database'] ]
                            self.log.debug('compress {}'.format(tar.ontology['tar file']))
                            tar.execute()
                    else:
                        self.abort('command {} is invalid'.format(tar.name))

    def export(self):
        export = Command('mongoexport', self.context, self.ontology)
        export.ontology.overlay(self.repository.mongodb)
        export.ontology['mongodb collection'] = 'home'
        try:
            self.env.prepare_to_write_to_path(export.ontology['mongoexport output path'], self.ontology['overwrite'])
        except (NoOverwriteError, PermissionDeniedError) as e:
            self.abort(str(e))
        else:
            # dump the tables into a staging directory
            for table in self.tables:
                if self.valid:
                    e = Command('mongoexport', self.context, self.ontology)
                    if export.valid:
                        e.ontology.overlay(self.repository.mongodb)
                        e.ontology['mongodb collection'] = table['collection']
                        self.log.debug('export table {}'.format(table['key']))
                        e.execute()
                    else:
                        self.abort('command {} is invalid'.format(e.name))

            # create a tarball
            if self.valid:
                tar = Command('tar', self.context, self.ontology)
                if tar.valid:
                    tar.ontology['dirname'] = self.node['work directory']
                    tar.ontology['archive name'] = self.node['timestamp']
                    try:
                        self.env.prepare_to_write_to_path(tar.ontology['tar file'], self.ontology['overwrite'])
                    except (NoOverwriteError, PermissionDeniedError) as e:
                        self.abort(str(e))
                    else:
                        tar.ontology['tar create'] = True
                        tar.ontology['positional'] = [ export.ontology['database'] ]
                        self.log.debug('compress {}'.format(tar.ontology['tar file']))
                        tar.execute()
                else:
                    self.abort('command {} is invalid'.format(tar.name))
