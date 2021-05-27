#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import io
import logging
import uuid
import signal
import json
import sys

from datetime import datetime, timedelta
import threading

from error import *
from ontology import Ontology, Document
from material import Resource
from command import Command

inode_type = lambda path: ( os.path.isfile(path) and 'file' ) or 'directory'
split_class = lambda x: (x[0:x.rfind('.')], x[x.rfind('.') + 1:])

class ProcessTable(object):
    def __init__(self, pid, gid):
        self.log = logging.getLogger('Queue')
        self.pid = pid
        self.gid = gid
        self.commands = {}
        self.thread = None
        self.token = threading.Condition()
        self.stopped = threading.Event()
        self.terminating = threading.Event()
        self.stopped.set()
        self.terminating.set()

    @property
    def length(self):
        return len(self.commands)

    def run(self):
        while not self.stopped.is_set():
            # running state
            with self.token:
                self.token.wait()

        self.log.debug('terminating all running processes')
        while not self.terminating.is_set():
            # in terminating state every add will notify and trigger termination
            with self.token:
                self.terminate()
                self.token.wait()

        self.clean()
        self.log.debug('no more running processes')

    def ignite(self):
        try:
            self.stopped.clear()
            self.terminating.clear()
            self.thread = threading.Thread(target=self.run, name='process table')
            self.thread.start()

        except(KeyboardInterrupt, SystemExit) as e:
            self.log.info('preemptive process table shutdown with signal %s', e)
            sys.exit(0)

    def stop(self):
        with self.token:
            self.stopped.set()
            self.token.notify()

    def halt(self):
        with self.token:
            if not self.stopped.is_set():
                self.stopped.set()
            self.terminating.set()
            self.token.notify()

    def add(self, command):
        with self.token:
            self.commands[command.pid] = command
            self.token.notify()

    def remove(self, command):
        with self.token:
            if command.pid is not None and command.pid in self.commands:
                del self.commands[command.pid]

    def terminate(self):
        for command in self.commands.values():
            command.terminate()

    def collect(self):
        from subprocess import Popen, PIPE
        decedents = None
        command = [ 'ps', '-e', '-o', 'pid,pgid,command' ]
        ps = Popen(command, stdout=PIPE, stderr=PIPE)
        output, error = ps.communicate()
        if output:
            decedents = []
            output = output.decode('utf8')
            all = [ line.split() for line in output.split('\n') ]
            pid = str(self.pid)
            pgid = str(self.gid)
            for process in all:
                if process:
                    try:
                        if process[0] != pid and process[1] == pgid:
                            decedents.append(
                                {
                                    'pid': int(process[0]),
                                    'pgid': int(process[1]),
                                    'command': process[2]
                                }
                            )
                    except ValueError: pass
        return decedents

    def clean(self):
        dangling = self.collect()
        if dangling:
            for process in dangling:
                try:
                    os.kill(process['pid'], signal.SIGKILL)
                    self.log.debug('SIGKILL sent to pid %s %s', process['pid'], process['command'])
                except ProcessLookupError: pass

class Condition(object):
    def __init__(self, task, ontology):
        self.log = logging.getLogger('Queue')
        self.task = task
        self.ontology = ontology

    @property
    def env(self):
        return self.queue.env

    @property
    def job(self):
        return self.task.job

    def evaluate(self):
        result = False
        if self.task.status == self.ontology['task status']:
            if self.ontology['condition scope'] == 'task':
                if self.ontology['task reference'] in self.job.journal['task']:
                    referenced = self.job.journal['task'][self.ontology['task reference']]
                    if referenced.status == self.ontology['task reference status']:
                        self.task.status = self.ontology['task status to apply']
                        result = True

            elif self.ontology['condition scope'] == 'group':
                if self.ontology['task reference'] in self.job.journal['task group']:
                    group = self.job.journal['task group'][self.ontology['task reference']]

                    if self.ontology['condition cardinality'] == 'all':
                        result = True
                        for referenced in group.values():
                            if referenced.status != self.ontology['task reference status']:
                                result = False
                                break

                        if result: self.task.status = self.ontology['task status to apply']

                    elif self.ontology['condition cardinality'] == 'any':
                        for referenced in group.values():
                            if referenced.status == self.ontology['task reference status']:
                                self.task.status = self.ontology['task status to apply']
                                result = True
                                break
        return result

class Scanner(object):
    def __init__(self, env, ontology):
        self.log = logging.getLogger('Queue')
        self.env = env
        self.ontology = ontology.project('ns/system/scanner')
        self._filter = None
        self._results = None
        self._ignored = None

        if 'filter' in self.ontology:
            self._filter = [] 
            for filter in self.ontology['filter']:
                match = self.env.expression['filter rule'].search(filter)
                if match:
                    f = match.groupdict()
                    try:
                        f['expression'] = re.compile(f['filter'], re.UNICODE)
                        self.log.debug('added filter \'%s\' with mode %s', f['filter'], f['mode'])
                        self._filter.append(f)
                    except re.error as err:
                        self.log.warning('failed to compile regular expression \'%s\' with mode %s because of %s', f['filter'], f['mode'], err)

            if not self._filter:
                self._filter = None

    @property
    def results(self):
        if self._results is None:
            self.search()
        return self._results

    @property
    def ignored(self):
        if self._ignored is None:
            self.search()
        return self._ignored

    @property
    def count(self):
        return len(self.results)

    def filter(self, decoded):
        # basic filtering of hidden files
        result = decoded['basename'][0] != self.env.constant['dot']

        if result and self._filter:
            for filter in self._filter:
                if filter['expression'].search(decoded['basename']) is not None:
                    if filter['mode'] == '-':
                        result = False
                        # self.log.debug('ignore %s', decoded['path'])
                    else:
                        pass
                        # self.log.debug('include %s', decoded['path'])
                    break
        return result

    def search(self):
        def collect(path, recursive, depth=1):
            result = []
            # The path might actually not exist, for instance a dangling symlink
            if os.path.exists(path):

                # allocate a new ontology
                decoded = Ontology( self.env, 'ns/medium/resource/url/decode',
                    {
                        'path': path,
                        'inode type': inode_type(path),
                        'dirname': os.path.dirname(path),
                        'basename': os.path.basename(path),
                    }
                )

                if self.filter(decoded):
                    # if the inode passes filtering add it to the result set
                    result.append(decoded)

                # Recursively scan decedent paths
                if decoded['inode type'] == 'directory' and (recursive or depth > 0) and not decoded['stop']:
                    for next in os.listdir(decoded['path']):
                        next = os.path.abspath(os.path.join(decoded['path'],next))
                        result.extend(collect(next, recursive, depth - 1))
                    self.log.debug('considering %d inodes in %s', len(result), decoded['path'])
            else:
                self.log.debug('ignoring non exiting path %s', path)
            return result

        inodes = []
        if self.ontology['scan path']:
            for path in self.ontology['scan path']:
                if os.path.exists(path):
                    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
                    inodes.extend(collect(path, self.ontology['recursive']))
                else:
                    self.log.error('path %s does not exist', path)

        self._results = []
        self._ignored = []
        if inodes:
            # Sort the list
            # We are still missing duplicate check.
            # this will wait for ontology hash and compare implementation
            inodes = sorted(inodes, key=lambda o: o['path'])

            # decode the inodes we found
            # only include ones that decode in the result set
            for inode in inodes:
                location = None
                try:
                    location = self.env.repository.resolve_inode(inode)
                except (UmidValidationError, UnresolvableResourceError) as error:
                    self._ignored.append({
                        'inode': inode,
                        'reason': str(error)
                    })
                else:
                    if location:
                        self._results.append(location)

        if self._results:
            self.log.info('%d locations resolved in %s', len(self._results), ' '.join(self.ontology['scan path']))

        if self._ignored:
            self.log.info('%d locations ignored in %s', len(self._ignored), ' '.join(self.ontology['scan path']))

class Queue(object):
    def __init__(self, env):
        self.log = logging.getLogger('Queue')
        self.env = env
        self.live = {}
        self.running = {}
        self.process_table = ProcessTable(self.env.system['pid'], self.env.system['pgid'])

        self.ontology = env.system.project('ns/system/queue')
        self.ontology['number of running jobs'] = 0
        self.ontology['number of pending jobs'] = 0
        self.ontology['slots'] = round(self.ontology['cores'] * self.ontology['thread per core ratio'])
        self.ontology['threads'] = 0

        self.thread = None
        self.token = threading.Condition()
        self.stopped = threading.Event()
        self.empty = threading.Event()
        self.empty.set()
        self.stopped.set()

    @property
    def capacity(self):
        return self.ontology['slots']

    @property
    def available(self):
        return self.capacity - self.utilization

    @property
    def utilization(self):
        return self.ontology['threads']

    @utilization.setter
    def utilization(self, value):
        with self.token:
            self.ontology['threads'] = value

    @property
    def demonized(self):
        return self.ontology['demonized']

    @property
    def interactive(self):
        return self.ontology['interactive']

    @property
    def blocking(self):
        return self.ontology['blocking']

    @property
    def pending(self):
        if self.ontology['pending'] is None:
            self.ontology['pending'] = []
        return self.ontology['pending']

    @property
    def feed(self):
        if self.ontology['feed'] is None:
            self.ontology['feed'] = {}
        return self.ontology['feed']

    def stop(self):
        self.stopped.set()
        for job in self.running.values():
            job.stop()
        self.process_table.stop()
        self.notify()

    def wait(self):
        self.empty.wait()        

    def ignite(self):
        try:
            self.log.debug(
                'queue established with %s slots and %s second polling',
                self.capacity,
                self.env.system['queue polling interval'])

            self.log.info('started version %s', self.env.system['tubo version'])
            self.process_table.ignite()

            self.stopped.clear()
            self.empty.clear()
            self.thread = threading.Thread(target=self.run, name='job queue')
            self.thread.start()
            if self.blocking:
                self.thread.join()

        except(KeyboardInterrupt, SystemExit) as e:
            self.log.info('preemptive queue shutdown with signal %s', e)
            self.stop() 
            sys.exit(0)

    def interpret(self, instruction):
        job = None
        if instruction:
            job = Ontology(self.env, 'ns/system/job')
            job.interpret(instruction)
            if job['action']:
                if job['implementation']:

                    # verify an old uri is not present
                    del job['job uri']

                    # give the job a new uuid
                    job['job uuid'] = str(uuid.uuid4())

                    job['host'] = self.env.host

                else:
                    self.log.error('could not infer implementation for action %s', job['action'])
                    job = None
            else:
                self.log.debug('job is missing an action\n{}'.format(self.env.to_json(job)))
                job = None
        return job

    def submit(self, instruction):
        job = self.interpret(instruction)
        if job is not None:
            url = 'http://{}:{}/web/q/job/{}/execution'.format(self.env.system['host'], self.env.system['api port'], job['job uuid'])
            document= Document(self.env, 'ns/system/job', {
                'head': {
                    'canonical': job['job uri'],
                    'genealogy': Ontology(self.env, 'ns/service/genealogy', {
                        'job uuid': job['job uuid'], 
                        'job status': 'pending',
                        'host': job['host']
                    })
                },
                'body': job,
            })
            self.env.resolver.save(document)
            self.log.info('submitted %s job %s', job['action'], url)
            self.log.debug('job submitted:\n{}'.format(self.env.to_json(document)))
        return job

    def push(self, instruction):
        job = self.interpret(instruction)
        if job is not None:
            self.pending.append(job)

    def poll(self):
        job = None
        with self.token:
            selected = None
            if self.demonized:
                # When running in demonized mode the queue feeds from the job queue table
                collection = self.env.repository.database['system_job_queue']
                reference = collection.find_and_modify (
                    sort = [('_id', 1)],
                    new = True,
                    query = {
                        'head.genealogy.job status': 'pending',
                        'head.genealogy.host': self.env.host
                    },
                    update = {
                        '$set': {
                            'head.genealogy.job status': 'running', 
                            'modified': datetime.utcnow()
                        }
                    }
                )
                if reference:
                    document = self.env.resolver.resolve(reference['head']['canonical'])
                    if document:
                        selected = document['body']

            elif self.pending:
                # when in interactive mode the queue will execute what ever jobs are in the pending list
                selected = self.pending.pop(0)

            if selected is not None:
                job = Job.create(self, selected)
                if job:
                    job.status = 'running'
        return job

    def synchronize(self):
        if self.demonized:
            with self.token:
                collection = self.env.repository.database['system_job_queue']
                cursor = collection.find({
                    'head.genealogy.job status': 'pending',
                    'head.genealogy.host': self.env.host
                })
                self.ontology['number of pending jobs'] = cursor.count()
                self.ontology['synchronized at'] = datetime.utcnow()

    def run(self):
        while not self.stopped.is_set():
            self.synchronize()
            with self.token:
                if self.available:
                    job = self.poll()
                    if job:
                        self.add(job)
                        job.ignite()
                        self.token.wait(self.env.system['queue polling interval'])
                    else:
                        self.token.wait(self.env.system['queue polling interval'])
                else:
                    self.token.wait(self.env.system['queue polling interval'])

                if not self.interactive and not self.pending:
                    self.stopped.set()

        # self.log.debug('job scheduling disabled')
        while self.running:
            with self.token:
                self.token.wait()

        self.process_table.halt()
        self.log.debug('all jobs done, shutting down queue')
        self.empty.set()

    def allocate(self, task):
        with self.token:
            self.utilization += task.ontology['threads']

    def free(self, task):
        with self.token:
            self.utilization -= task.ontology['threads']
            self.token.notify()

    def notify(self):
        with self.token:
            self.token.notify()

    def add(self, job):
        with self.token:
            self.running[job.uuid] = job
            self.live[job.node['job execution uri']] = job.document
            self.feed[job.node['job execution uri']] = job.document.body['job']
            self.ontology['number of running jobs'] = len(self.running)

    def remove(self, job):
        with self.token:
            del self.live[job.node['job execution uri']]
            del self.feed[job.node['job execution uri']]
            del self.running[job.uuid]
            self.ontology['number of running jobs'] = len(self.running)
            self.token.notify()

class Job(object):
    def __init__(self, queue, node):
        self.log = logging.getLogger('Queue')
        self.queue = queue
        self.document = Document(self.env, 'ns/system/job/execution', {
            'head': {
                'canonical': node['job execution uri'],
                'genealogy': node['job'].project('ns/service/genealogy')
            },
            'body': node,
        })
        self.journal = {
            'task': {}, 
            'task group': {},
            'pending': [],
            'ready': [],
            'running': {}
        }

        self.node['task executions'] = []
        self.node['ignored'] = []
        self.node['number of pending tasks'] = 0
        self.node['number of ready tasks'] = 0
        self.node['number of running tasks'] = 0
        self.node['number of completed tasks'] = 0
        self.node['number of aborted tasks'] = 0
        self.ontology['threads'] = 0

        self.thread = None
        self.token = threading.Condition()
        self.stopped = threading.Event()

    def __str__(self):
        return '{}.{}'.format(self.action, self.uuid)

    @classmethod
    def create(cls, queue, ontology):
        instance = None
        if queue and ontology:
            job = ontology.project('ns/system/job')
            if job['action']:
                if job['job uri']:
                    if job['implementation']:
                        module, name  = split_class(job['implementation'])
                        try:
                            implementation_module = __import__(module, fromlist=[name])
                            implementation_class = getattr(implementation_module, name)
                            instance = implementation_class(queue, 
                                Ontology(queue.env, 'ns/system/job/execution', {
                                    'job': job,
                                    'host': queue.env.host,
                                    'created': datetime.utcnow(),
                                    'job uuid': job['job uuid']
                                })
                            )
                        except ImportError as e:
                            queue.log.error('no module named %s found when attempting to instantiate %s job implementation', module, job['action'])
                            queue.log.debug(e)
                        except AttributeError as e:
                            queue.log.error('class %s not defined in module %s when attempting to instantiate %s job implementation', name, module, job['action'])
                            queue.log.debug(e)
                        except Exception as e:
                            queue.log.error('%s %s', type(e), e)
                    else:
                        queue.log.error('could not infer implementation for action %s', job['action'])
                else:
                    queue.log.error('job is missing a valid URI\n{}'.format(self.env.to_json(job)))
            else:
                queue.log.error('job is missing an action\n{}'.format(self.env.to_json(job)))
        return instance

    @property
    def capacity(self):
        return self.ontology['slots']

    @property
    def available(self):
        return 1 if self.capacity is None else self.capacity - self.utilization

    @property
    def utilization(self):
        return self.ontology['threads']

    @utilization.setter
    def utilization(self, value):
        with self.token:
            self.ontology['threads'] = value

    def allocate(self, task):
        with self.token:
            self.utilization += task.ontology['threads']

    def free(self, task):
        with self.token:
            self.utilization -= task.ontology['threads']
            self.token.notify()

    @property
    def env(self):
        return self.queue.env

    @property
    def uuid(self):
        return self.node['job']['job uuid']

    @property
    def status(self):
        return self.node['job status']

    @status.setter
    def status(self, value):
        self.node['job status'] = value

    @property
    def valid(self):
        return self.node and self.ontology and self.status != 'aborted'

    @property
    def node(self):
        return self.document.body

    @property
    def ontology(self):
        return self.node['job']

    @property
    def simulated(self):
        return self.ontology['debug']

    @property
    def action(self):
        return self.ontology['action']

    @property
    def pending(self):
        return self.journal['pending']

    @property
    def ready(self):
        return self.journal['ready']

    @property
    def running(self):
        return self.journal['running']

    def stop(self):
        self.stopped.set()

    def load(self):
        self.node['started'] = datetime.utcnow()
        self.log.info('job %s started', str(self))

    def push(self, task):
        if task.status == 'pending':
            with self.token:
                # index the task by task uuid
                self.journal['task'][task.uuid] = task

                # start a new group if the task's group is not yet defined
                if task.group not in self.journal['task group']:
                    self.journal['task group'][task.group] = {}

                # add the task to the group
                self.journal['task group'][task.group][task.uuid] = task

                self.node['task executions'].append(task.node)
                self.pending.append(task)
                self.node['number of pending tasks'] = len(self.pending)

    def poll(self):
        selected = None
        with self.token:
            if self.ready:
                selected = self.ready.pop(0)
                self.node['number of ready tasks'] = len(self.ready)

                possible = min(self.queue.available, selected.ontology['task cores'])
                fraction = min((possible / self.queue.available), self.queue.ontology['max of free portion'])
                selected.threads = round(self.queue.available * fraction)

                self.running[selected.uuid] = selected
                self.node['number of running tasks'] = len(self.running)
        return selected

    def ignite(self):
        try:
            self.thread = threading.Thread(target=self.run, name=self.uuid)
            self.thread.start()

        except(KeyboardInterrupt, SystemExit) as e:
            self.log.debug('job %s received halt signal', str(self))
            self.stopped.set()
            sys.exit(0)

    def evaluate(self):
        if self.pending:
            with self.token:
                remaining = []
                for task in self.pending:
                    task.evaluate()
                    if task.status == 'ready':
                        self.ready.append(task)

                    elif task.status == 'pending':
                        remaining.append(task)

                self.journal['pending'] = remaining
                self.node['number of ready tasks'] = len(self.ready)
                self.node['number of pending tasks'] = len(self.pending)

    def run(self):
        self.load()
        if self.valid:
            while not self.stopped.is_set():
                with self.token:
                    self.evaluate()
                    if self.ready and self.available:
                        self.queue.token.acquire()
                        if self.queue.available:
                            selected = self.poll()
                            if selected is not None:
                                self.allocate(selected)
                                self.queue.allocate(selected)
                                self.queue.token.release()
                                selected.ignite()
                            else:
                                self.queue.token.notify()
                                self.queue.token.release()
                                self.token.wait(self.env.system['job polling interval'])
                        else:
                            self.queue.token.release()
                            self.token.wait(self.env.system['job polling interval'])
                    else:
                        if self.running:
                            self.token.wait(self.env.system['job polling interval'])
                        else:
                            self.stop()
                        self.queue.notify()

        while self.running:
            with self.token:
                self.token.wait()

        self.unload()

    def unload(self):
        self.node['ended'] = datetime.utcnow()
        self.node['duration'] = (self.node['ended'] - self.node['started']).total_seconds()
        if not self.node['ignored']: del self.node['ignored']
        if not self.node['task executions']: del self.node['task executions']
        if self.valid: self.status = 'completed'
        self.env.resolver.remove(self.ontology['job uri'])
        self.queue.remove(self)
        if self.node['job']['save job execution']: self.save()
        self.log.info('job %s done in %s', str(self), str(timedelta(seconds=self.node['duration'])))

    def save(self):
        self.env.resolver.save(self.document)
        self.log.info('job logged at %s', self.node['job execution uri'])

    def remove(self, task):
        with self.token:
            del self.running[task.uuid]
            self.node['number of running tasks'] = len(self.running)

            if task.status == 'completed':
                self.node['number of completed tasks'] += 1

            elif task.status == 'aborted':
                self.node['number of aborted tasks'] += 1

            self.token.notify()

class Task(object):
    def __init__(self, job, ontology):
        self.log = logging.getLogger('Queue')
        self.job = job
        self.action = None
        self.condition = None
        self._preset = None

        self.node = Ontology(self.env, 'ns/system/task/execution')        
        self.node['task'] = ontology.project('ns/system/task')
        self.node['task']['cores'] = self.queue.ontology['cores']

        self.node['host'] = self.job.node['host']
        self.node['task uuid'] = str(uuid.uuid4())
        self.node['job uuid'] = self.job.uuid
        self.node['created'] = datetime.utcnow()
        self.node['task status'] = 'pending'
        self.node['commands'] = []
        self.node['errors'] = []
        self.node['task group uuid'] = self.node['task uuid']

        self.products = []
        self.node['products'] = []

        # ensure work directory
        self.node['work directory']

        # Create a context ontology
        self.context = Ontology(self.env, 'ns/system/context')
        self.context['queue'] = self.queue
        self.context['job execution'] = self.job.node
        self.context['task execution'] = self.node

        self.thread = None

    def __str__(self):
        return '{}.{}'.format(self.ontology['action'], self.uuid)

    @property
    def env(self):
        return self.job.env

    @property
    def repository(self):
        return self.env.repository

    @property
    def queue(self):
        return self.job.queue

    @property
    def uuid(self):
        return self.node['task uuid']

    @property
    def group(self):
        return self.node['task group uuid']

    @group.setter
    def group(self, value):
        self.node['task group uuid'] = value

    @property
    def status(self):
        return self.node['task status']

    @status.setter
    def status(self, value):
        self.node['task status'] = value

    @property
    def threads(self):
        return self.ontology['threads']

    @threads.setter
    def threads(self, value):
        self.ontology['threads'] = value

    @property
    def valid(self):
        return self.status != 'aborted'

    @property
    def ontology(self):
        return self.node['task']

    @property
    def simulated(self):
        return self.node['task']['debug']

    @property
    def command(self):
        return self.node['commands']

    @property
    def preset(self):
        if self._preset is None:
            if 'preset' in self.ontology and self.ontology['preset'] in self.env.preset:
                self._preset = self.env.preset[self.ontology['preset']]
        return self._preset

    def evaluate(self):
        if self.condition:
            for condition in self.condition:
                condition.evaluate()
        else:
            self.status = 'ready'

    def add_product(self, product):
        if product is not None:
            self.products.append(product)
            self.node['products'].append(product.location)

    def produce(self, origin, override=None):
        location = Ontology.clone(origin)

        # allow the location to recalculate those concepts 
        for word in [
            'basename',
            'canonic basename',
            'canonic dirname',
            'dirname',
            'home id',
            'host',
            'path digest',
            'path',
            'umid',
            'volume path',
            'volume',            
        ]: del location[word]

        # absorb those from the task
        location.absorb(self.ontology, ('volume', 'profile', 'compression'))

        # if an override was given apply it 
        if override:
            for e in override: location[e] = override[e]

        # after all modifications expand the home
        self.env.expand_home(location)

        product = Resource.create(self.env, location, self.context)
        self.add_product(product)
        self.log.debug('producing %s', product.path)

        return product

    def constrain(self, node):
        if self.condition is None:
            self.node['conditions'] = []
            self.condition = []

        condition = Condition(self, Ontology(self.env, "ns/system/condition", node))
        self.node['conditions'].append(condition.ontology)
        self.condition.append(condition)

    def load(self):
        self.node['started'] = datetime.utcnow()
        self.log.info('task %s started with %s threads', str(self), self.ontology['threads'])
        if self.valid:
            if self.preset:
                # if the action is defined in the preset, the preset supports the action
                if self.ontology['action'] in self.preset['action']:

                    # locate a method that implements the action
                    self.action = getattr(self, self.ontology['method'], None)

                    if self.action is None:
                        raise ConfigurationError('action {} is not implemented'.format(self.ontology['action']))
                else:
                    raise ConfigurationError('action {} is not defined for preset {}'.format(self.ontology['action'], self.ontology['preset']))
            else:
                raise ConfigurationError('preset could not be determined')

    def ignite(self):
        try:
            self.thread = threading.Thread(target=self.run, name=self.uuid)
            self.thread.start()
        except(KeyboardInterrupt, SystemExit) as e:
            self.log.debug('task %s received halt signal', str(self))
            sys.exit(0)

    def run(self):
        try:
            self.load()
            if self.valid:
                self.status = 'running'
                self.action()
        except (TuboError) as e:
            self.abort(str(e))
        self.unload()

    def unload(self):
        if self.products:
            if self.valid:
                for product in self.products:
                    if product.exists:
                        o = self.job.ontology.project('ns/system/task')
                        del o['preset']
                        del o['overwrite']
                        del o['task cores']
                        del o['threads']
                        o['action'] = 'crawl'
                        t = ResourceTask(self.job, o, product.location)
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
                    product.unload()
        else:
            del self.node['products']

        if self.node['commands']:
            for command in self.node['commands']:
                del command['ontology']['password']
        else:
            del self.node['commands']

        if not self.node['errors']:
            del self.node['errors']

        self.env.clean_directory(self.node['work directory'])

        if self.valid: self.status = 'completed'

        self.queue.free(self)
        self.job.free(self)
        self.job.remove(self)
        self.node['ended'] = datetime.utcnow()
        duration = self.node['ended'] - self.node['started']
        self.node['duration'] = duration.total_seconds()
        self.log.info('task %s done with status %s in %s', str(self), self.status, str(duration))

    def abort(self, message, status='aborted'):
        self.node['errors'].append(message)
        self.status = status
        self.log.warning('task %s aborted because %s', str(self), message)

class ResourceJob(Job):
    def __init__(self, queue, node):
        Job.__init__(self, queue, node)

    def load(self):
        Job.load(self)
        scanner = Scanner(self.env, self.ontology)
        if scanner.ignored:
            self.node['ignored'].extend(scanner.ignored)
        if scanner.results:
            count = 0
            for location in scanner.results:
                self.push(ResourceTask(self, self.ontology, location))
                count += 1
            self.log.debug('%d %s tasks queued in job %s', count, self.action, self.uuid)

class ResourceTask(Task):
    def __init__(self, job, ontology, location):
        Task.__init__(self, job, ontology)
        self.location = location
        self.resource = None
        self.node['origins'] = []

    def load(self):
        Task.load(self)
        if self.location:
            self.resource = Resource.create(self.env, self.location, self.context)
        else:
            raise InvalidResourceError('invalid resource location was provided')

    def unload(self):
        if self.resource:
            if self.valid:
                self.resource.unload()
        else:
            del self.node['origins']

        Task.unload(self)

    def info(self):
        try:
            if self.resource.node is not None:
                document = json.dumps(self.resource.node, 
                    ensure_ascii=False, 
                    sort_keys=True, 
                    indent=4, 
                    default=self.env.default_json_handler
                )
                print(document)
            else:
                self.abort('resource not indexable')
        except (NoOverwriteError, PermissionDeniedError) as e:
            self.abort(str(e))

    def crawl(self):
        try:
            if self.resource.node is None:
                self.abort('resource not indexable')
        except (NoOverwriteError, PermissionDeniedError) as e:
            self.abort(str(e))

    def copy(self):
        product = self.produce(self.resource.origin)
        if self.resource.local or product.local:
            try:
                if product.local:
                    self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
                else:
                    self.env.prepare_to_write_to_remote_path(product.host, product.path, self.ontology['overwrite'])
            except (NoOverwriteError, PermissionDeniedError) as e:
                self.abort(str(e))
            else:
                rsync = Command('rsync', self.context)
                if rsync.valid:
                    path = self.resource.qualified_path
                    if self.resource.location['inode type'] == 'directory':
                        rsync.ontology['recursive rsync'] = True
                        path += '/'
                    rsync.ontology['positional'] = [ path, product.qualified_path ]
                    self.log.debug('copy {} --> {}'.format(path, product.qualified_path))
                    rsync.execute()
                else:
                    self.abort('command {} is invalid'.format(rsync.name))
        else:
            self.abort('either source or destination must be local')

    def symlink(self):
        product = self.produce(self.resource.origin)
        if self.resource.local and product.local:
            try:
                self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
            except (NoOverwriteError, PermissionDeniedError) as e:
                self.abort(str(e))
            else:
                ln = Command('ln', self.context)
                if ln.valid:
                    ln.ontology['symbolic ln'] = True
                    ln.ontology['positional'] = [ self.resource.qualified_path, product.qualified_path ]
                    self.log.debug('symlink {} --> {}'.format(self.resource.qualified_path, product.qualified_path))
                    ln.execute()
                else:
                    self.abort('command {} is invalid'.format(ln.name))
        else:
            self.abort('both source and destination must be local')

    def move(self):
        # A move task is composed of a copy task
        # followed by a delete task only executed if the copy task is successful 
        product = self.produce(self.resource.origin)
        if product.location['host'] == self.env.host:
            if os.path.exists(product.path) and os.path.samefile(self.resource.path, product.path):
                self.log.debug('no move necessary for %s', str(self))
            else:
                try:
                    self.env.prepare_to_write_to_path(product.path, self.ontology['overwrite'])
                except (NoOverwriteError, PermissionDeniedError) as e:
                    self.abort(str(e))
                else:
                    # first copy the resource to its new location
                    if self.valid:
                        rsync = Command('rsync', self.context)
                        if rsync.valid:
                            path = os.path.realpath(self.resource.path)
                            if self.resource.location['inode type'] == 'directory':
                                rsync.ontology['recursive rsync'] = True
                                path += '/'
                            rsync.ontology['positional'] = [ path, product.path ]
                            self.log.debug('copy {} --> {}'.format(path, product.path))
                            rsync.execute()
                        else:
                            self.abort('command {} is invalid'.format(rsync.name))

                    # if the copy was successful delete the resource
                    if self.valid:
                        rm = Command('rm', self.context)
                        if rm.valid:
                            rm.ontology['force'] = True
                            if self.resource.location['inode type'] == 'directory':
                                rm.ontology['recursive rm'] = True
                            rm.ontology['positional'] = [ self.resource.path ]
                            self.log.debug('remove {}'.format(self.resource.path))
                            rm.execute()
                        else:
                            self.abort('command {} is invalid'.format(rm.name))

                    # if the deletion was sucessful cleanup the path
                    if self.valid:
                        self.env.clean_path(self.resource.path)
        else:
            self.abort('remote move not yet implemented')

    def delete(self):
        if self.resource.local:
            try:
                self.env.check_file_permission(self.resource.path)
            except PermissionDeniedError as e:
                self.abort(str(e))
            else:
                rm = Command('rm', self.context)
                if rm.valid:
                    rm.ontology['force'] = True
                    if self.resource.location['inode type'] == 'directory':
                        rm.ontology['recursive rm'] = True
                    rm.ontology['positional'] = [ self.resource.path ]
                    self.log.debug('remove {}'.format(self.resource.path))
                    rm.execute()
                    self.env.clean_path(self.resource.path)
                else:
                    self.abort('command {} is invalid'.format(rm.name))
        else:
            self.abort('can only delete local resources')

    def tar(self):
        if self.resource.node is not None:
            if self.resource.location['media kind'] == 50 and self.resource.location['inode type'] == 'directory':
                tar = Command('tar', self.context, self.ontology)
                if tar.valid:
                    override = { 'extension': 'tar', 'inode type': 'file', 'compression': tar.ontology['compression'] }
                    if self.resource.location['kind'] == 'ihrf': override['kind'] = 'ihrz'
                    elif self.resource.location['kind'] == 'imrf': override['kind'] = 'imrz'

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

    def untar(self):
        if self.resource.node is not None:
            if self.resource.location['media kind'] == 50 and self.resource.location['inode type'] == 'file' and self.resource.location['extension'] == 'tar':
                tar = Command('tar', self.context, self.ontology)
                if 'compression' not in self.ontology:
                    tar.ontology['compression'] = self.resource.location['compression']

                if tar.valid:
                    override = { 'extension': None, 'compression': None, 'inode type': 'directory' }
                    if self.resource.location['kind'] == 'ihrz': override['kind'] = 'ihrf'
                    elif self.resource.location['kind'] == 'imrz': override['kind'] = 'imrf'
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
