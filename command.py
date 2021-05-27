# -*- coding: utf-8 -*-

import logging
import sys
import os
import io
from subprocess import Popen, PIPE
from datetime import timedelta, datetime

from error import *
from ontology import Ontology
import threading

class Command(object):
    def __init__(self, name, context, ontology=None):
        self.log = logging.getLogger('Command')
        self.context = context
        self.valid = False
        self.process = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.output = None
        self.error = None
        self._prototype = None
        self._preset = None
        self._errorcode = None
        self._need_work_directory = False
        self.node = {
            'name': name,
            'debug': False,
            'return code': None,
            'executable': [],
            'buffer size': 0,
            'cwd': None,
            'env': None,
            'shell': False,
            'ontology': None,
        }

        if self.prototype is not None:
            if self.prototype['available']:
                self.valid = True

                self.executable.append(self.prototype['executable'])
                if self.implementation == 'interpreted':
                    self.executable.append(self.prototype['script'])

                elif self.implementation == 'java':
                    if 'jvm arguments' in self.prototype:
                        for argument in self.prototype['jvm arguments']:
                            self.executable.append(argument)
                    self.executable.append('-jar')
                    self.executable.append(self.prototype['jar'])

                if 'namespace' in self.prototype and self.prototype['namespace']:
                    self.node['ontology'] = Ontology(self.env, self.prototype['namespace'])
                else:
                    self.node['ontology'] = Ontology(self.env, 'ns/program/default')

                # If an environment is specificed it will override the current process environment
                if 'environment' in self.prototype and self.prototype['environment']:
                    self.environment = self.prototype['environment']

                # If a sub command is present append it to the executable list
                if 'sub command' in self.prototype:
                    self.executable.append(self.prototype['sub command'])

                if 'task execution' in self.context and 'task' in self.context['task execution']:
                    # Populate the ontology with command parameters from the preset
                    self.ontology.overlay(self.preset)

                    # Than override with parameters provided to the task
                    self.ontology.overlay(self.context['task execution']['task'])
                    self.node['debug'] = self.context['task execution']['task']['debug']

                # Than overlay with explicitly provided parameters
                if ontology is not None:
                    self.ontology.overlay(ontology)

                # Work directory taken from task execution
                if 'work directory' not in self.ontology:
                    if 'task execution' in self.context:
                        self.ontology['work directory'] = self.context['task execution']['work directory']

                # By default a task is executed in a shell rooted at the work directory
                if 'work directory' in self.ontology:
                    self.cwd = self.ontology['work directory']

                # add the command node to the context
                self.context['task execution']['commands'].append(self.node)

            else:
                self.log.debug('command %s is unavailable', self.name)
        else:
            self.log.error('unknown command %s', self.name)

    @property
    def env(self):
        return self.context.env

    @property
    def name(self):
        return self.node['name']

    @property
    def implementation(self):
        return self.prototype['implementation']

    @property
    def prototype(self):
        if self._prototype is None:
            if self.name in self.env.command:
                self._prototype = self.env.command[self.name]
        return self._prototype

    @property
    def ontology(self):
        return self.node['ontology']

    @property
    def simulated(self):
        return self.node['debug']

    @property
    def pid(self):
        if self.process is not None:
            return self.process.pid
        else:
            return None

    @property
    def returncode(self):
        return self.node['return code']

    @property
    def errorcode(self):
        if self._errorcode is None and 'error code' in self.prototype:
            self._errorcode = dict((code['code'], code) for code in self.prototype['error code'])
        return self._errorcode

    @property
    def cwd(self):
        return self.node['cwd']

    @cwd.setter
    def cwd(self, value):
        self.node['cwd'] = value

    @property
    def environment(self):
        return self.node['env']

    @environment.setter
    def environment(self, value):
        self.node['env'] = value

    @property
    def executable(self):
        return self.node['executable']

    @property
    def preset(self):
        if self._preset is None:
            if self.context['task execution']['task']['preset'] in self.env.preset:
                preset = self.env.preset[self.context['task execution']['task']['preset']]

                if preset and 'action' in preset and \
                self.context['task execution']['task']['action'] in preset['action'] and \
                preset['action'][self.context['task execution']['task']['action']] and \
                self.name in preset['action'][self.context['task execution']['task']['action']]:
                    self._preset = preset['action'][self.context['task execution']['task']['action']][self.name]
            if self._preset is None: self._preset = {}
        return self._preset

    def kill(self):
        if self.process is not None:
            self.log.info('sending SIGKILL to %s with pid %s', self.name, self.pid)
            try:
                self.process.kill()
            except ProcessLookupError: pass

    def terminate(self):
        if self.process is not None:
            try:
                self.process.terminate()
                self.log.info('SIGTERM sent to %s with pid %s', self.name, self.pid)
            except ProcessLookupError: pass

    def encode(self, safe=False):
        # assemble the command line
        assembled = self.assemble(safe)

        encoded = []
        for e in assembled:
            if self.env.constant['space'] in e:
                encoded.append('"{}"'.format(e))
            else:
                encoded.append(e)
        return self.env.constant['space'].join(encoded)

    def assemble(self, safe=False):
        assembled = []

        # Start with the executing binary or script
        assembled.extend(self.executable)

        # encode the optional parameters
        if self.prototype['style'] == 'POSIX':
            for prototype in self.ontology.namespace.element.values():
                if prototype.key in self.ontology:
                    value = self.ontology[prototype.key]
                    if value is not None and 'cli' in prototype.node and prototype.node['cli'] is not None:
                        if prototype.plural:
                            for v in value:
                                assembled.append(prototype.node['cli'])
                                assembled.append(str(v))
                        else:
                            if prototype.type == 'boolean':
                                if value: assembled.append(prototype.node['cli'])
                            else:
                                assembled.append(prototype.node['cli'])
                                if prototype.key == 'password' and safe:
                                    assembled.append(self.ontology['hidden password'])
                                else:
                                    assembled.append(str(value))

        elif self.prototype['style'] == 'picard':
            for prototype in self.ontology.namespace.element.values():
                if prototype.key in self.ontology:
                    value = self.ontology[prototype.key]
                    if value is not None and 'cli' in prototype.node and prototype.node['cli'] is not None:
                        if prototype.plural:
                            for v in value:
                                assembled.append('{}={}'.format(prototype.node['cli'], str(v)))
                        else:
                            if prototype.type == 'boolean':
                                assembled.append('{}={}'.format(prototype.node['cli'], str(value).lower()))
                            else:
                                assembled.append('{}={}'.format(prototype.node['cli'], str(value)))

        elif self.prototype['style'] == 'mediainfo':
            for prototype in self.ontology.namespace.element.values():
                if prototype.key in self.ontology:
                    value = self.ontology[prototype.key]
                    if value is not None and 'cli' in prototype.node and prototype.node['cli'] is not None:
                        if prototype.plural:
                            for v in value:
                                assembled.append('{}={}'.format(prototype.node['cli'], str(v)))
                        else:
                            if prototype.type == 'boolean':
                                if value: assembled.append(prototype.node['cli'])
                            else:
                                assembled.append('{}={}'.format(prototype.node['cli'], str(value)))

        # encode positional parameters
        if 'positional' in self.ontology and self.ontology['positional']:
            assembled.extend(self.ontology['positional'])

        return assembled

    def execute(self):
        if not self.simulated:
            self.node['started'] = datetime.utcnow()

            self.env.prepare_directory(self.ontology['work directory'])
            if self.stdout is None and self.prototype['stdout'] is not None:
                if self.prototype['stdout'] == 'file':
                    # attempt to open stdout file for appending
                    if self.ontology['stdout path'] is not None:
                        try:
                            self.stdout = io.open(self.ontology['stdout path'], 'ab')
                        except OSError as error:
                            self.log.error(str(error))

                elif self.prototype['stdout'] == 'pipe':
                    # will not redirect to caller's stdout
                    self.stdout = PIPE

            if self.stderr is None:
                if self.prototype['stderr'] == 'file':
                    # attempt to open stderr file for appending
                    if self.ontology['stderr path'] is not None:
                        try:
                            self.stderr = io.open(self.ontology['stderr path'], 'ab')
                        except OSError as error:
                            self.log.error(str(error))

                elif self.prototype['stderr'] == 'pipe':
                    # will not redirect to caller's stderr
                    self.stderr = PIPE

            # assemble the command line
            assembled = self.assemble()

            # log the command
            self.log.debug('execute: %s', self.encode(True))

            # Start a process object
            self.process = Popen(
                args=assembled,
                bufsize=self.node['buffer size'],
                cwd=self.node['cwd'],
                env=self.node['env'],
                shell=self.node['shell'],
                stdin=self.stdin,
                stdout=self.stdout,
                stderr=self.stderr
            )

            # add a reference to the global running process table
            self.context['queue'].process_table.add(self)

            # execute the process
            self.output, self.error = self.process.communicate()

            # remove the reference from the global running process table
            self.context['queue'].process_table.remove(self)

            # convert the byte output and error to utf8 string
            if self.output is not None: self.output = self.output.decode('utf8')
            if self.error is not None: self.error = self.error.decode('utf8')

            # set the return code
            self.node['return code'] = self.process.returncode

            # attempt to close stdout file
            if self.prototype['stdout'] == 'file':
                try:
                    self.stdout.close()
                    self.stdout = None
                except OSError as error:
                    self.log.error(str(error))

            # attempt to close stderr file
            if self.prototype['stderr'] == 'file':
                try:
                    self.stderr.close()
                    self.stderr = None
                except OSError as error:
                    self.log.error(str(error))

            self.node['ended'] = datetime.utcnow()
            self.node['duration'] = (self.node['ended'] - self.node['started']).total_seconds()

            # if the command returned an error abort the task and log the error
            if self.returncode != 0:
                message = '{} returned {}'.format(self.name, self.returncode)
                if self.errorcode is not None:
                    if self.returncode in self.errorcode:
                        message = '{} : {}'.format(message, self.errorcode[self.returncode]['message'])
                raise UnsuccessfulTerminationError(message)

        # debug mode only prints the encoded command
        else: print(self.encode(True))
