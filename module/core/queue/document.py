#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import json
from queue import Job, Task
from ontology import Ontology
from error import *

class DocumentJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)

    def load(self):
        Job.load(self)
        if self.ontology['uris']:
            for uri in self.ontology['uris']:
                self.push(DocumentTask(self, self.ontology.project('ns/system/task'), uri))

class DocumentTask(Task):
    def __init__(self, job, ontology, uri):
        Task.__init__(self, job, ontology)
        self.uri = uri
        self.document = None

        if self.uri is None:
            self.abort('an invalid resource uri was provided')

    def load(self):
        Task.load(self)
        if self.valid:
            self.document = self.env.resolver.resolve(self.uri, self.ontology['genealogy'], self.context)
            if self.document is None:
                self.abort('document {} could not be located'.format(self.uri))

    def get(self):
        try:
            print(json.dumps(self.document, ensure_ascii=False, sort_keys=True, indent=4, default=self.env.default_json_handler))
        except (TuboError) as e:
            self.abort(str(e))

    def set(self):
        if self.ontology['genealogy']:
            self.document['head']['genealogy'].overlay(self.ontology['genealogy'])
            self.env.resolver.save(self.document)
            self.document = self.env.resolver.resolve(self.uri, self.ontology['genealogy'])

    def drop(self):
        self.env.resolver.remove(self.uri)
