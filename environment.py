# -*- coding: utf-8 -*-
import os
import re
import io
import logging
import copy
import hashlib
import json
import pickle
import pymongo
import signal
import sys
import time
import threading

from io import BytesIO
from datetime import timedelta, datetime
from argparse import ArgumentParser
from pymongo import MongoClient
from bson.objectid import ObjectId
from collections import OrderedDict

from error import *
from ontology import Ontology, Enumeration, PrototypeSpace, Rule, Space, Umid
from service import Resolver
from rest import RestResolver

check = lambda node: 'enabled' not in node or node['enabled']

# register a termination signals
def termination_handler(signal, frame):
    sys.exit(0)

def to_json(node):
    return json.dumps(node, sort_keys=True, indent=4, ensure_ascii=False)

signal.signal(signal.SIGTERM, termination_handler)
signal.signal(signal.SIGINT, termination_handler)

class Configuration(object):
    def __init__(self):
        self.log = logging.getLogger('Configuration')
        self.dirty = True
        self.node = None
        self.boot()
        self.load()
        checkpoint = self.snapshot_sha1
        if 'checkpoint sha1' in self.node and checkpoint == self.node['checkpoint sha1']:
            # if the checkpoint sha1 match we can skip initialization and load the snapshot
            self.log.debug('loading configuration snapshot %s', self.node['snapshot sha1'])
            self.state = self.node['snapshot']
        else:
            self.dirty = True
            self.node['checkpoint sha1'] = checkpoint
            self.apply_volume_routing()
            self.sanitize()
            self.sort()
            self.validate()
            self.check()
            self.flush()
        self.apply_command_availability()

    @property
    def home(self):
        return self.ontology['tubo home']

    @property
    def system_home(self):
        return self.ontology['tubo system home']

    @property
    def salt(self):
        return self.ontology['salt']

    @property
    def state(self):
        return self.node['state']

    @state.setter
    def state(self, value):
        self.node['state'] = value

    @property
    def snapshot_sha1(self):
        result = None
        if self.node['order']:
            # changing the salt will cause a snapshot flush on next load everywhere
            content = [ self.salt ]
            if self.node['order']:
                content.extend(self.node['order'])
            result = hashlib.sha1(''.join(content).encode('utf8')).hexdigest()
        return result

    @property
    def instruction(self):
        return self.node['instruction']

    @property
    def record(self):
        return self.node['record']

    @property
    def section(self):
        return self.ontology['section']

    @property
    def module(self):
        return self.state['module']

    def boot(self):
        try:
            with io.open(os.path.join(os.path.dirname(__file__), 'boot.json'), 'rb') as f:
                self.ontology = json.loads(f.read().decode('utf8'))
        except OSError as e:
            raise ConfigurationError('error reading boot.json')
        except ValueError as e:
            raise ConfigurationError('error parsing boot.json because {}'.format(str(e)))
        else:
            self.ontology['section'] = OrderedDict([e for e in sorted(self.ontology['section'].items(), key=lambda x: x[1]['order'])])
            for module in self.ontology['module']:
                if 'base' in module:
                    module['absolute path'] = os.path.join(module['base'], module['path'])
                else:
                    module['absolute path'] = os.path.join(os.path.dirname(__file__), module['path'])
            self.dirty = False

        if 'TUBO_SYSTEM_HOME' in os.environ:
            self.ontology['tubo system home'] = os.environ['TUBO_SYSTEM_HOME']
        self.ontology['tubo system home'] = os.path.expanduser(os.path.expandvars(self.system_home))
        self.log.debug('system home directory set to %s', self.system_home)

        if 'TUBO_HOME' in os.environ:
            self.ontology['tubo home'] = os.environ['TUBO_HOME']
        self.ontology['tubo home'] = os.path.expanduser(os.path.expandvars(self.home))
        self.log.debug('home directory set to %s', self.home)
        self.ontology['setting cache path'] = os.path.join(self.home, self.ontology['setting cache path'])

        for key, section in self.section.items():
            section['key'] = key
            if 'method' in section:
                action = getattr(self, section['method'], None)
                if action is not None:
                    section['handler'] = action

    def ignite(self, command):
        self.apply_command_line(command)
        self.apply_default_host_and_language()
        self.validate_system()

    def flush(self):
        if self.dirty:
            try:
                with io.open(self.ontology['setting cache path'], 'wb') as f:
                    snapshot = {
                        'created': str(datetime.now()),
                        'snapshot': self.take_snapshot(),
                        'snapshot sha1': self.snapshot_sha1,
                        'checkpoint sha1': self.node['checkpoint sha1'],
                        'record': self.node['record'],
                    }
                    pickle.dump(snapshot, f)
                    # print(to_json(snapshot))
                self.log.debug('saved snapshot %s', snapshot['snapshot sha1'])
                self.dirty = False
            except OSError as e:
                self.log.error('failed writing configuration cache to %s', self.ontology['setting cache path'])
                self.log.debug(str(e))

    # loading...
    def load(self, ):
        # load an existing pickled state
        self.load_cache()

        # load modules into state
        for module in self.ontology['module']:
            if 'enabled' not in module or module['enabled']:
                self.load_module(module)

        # finally load setting
        self.load_setting()
        self.apply_path_expansion()
        self.apply_version()

    def load_cache(self):
        if os.path.exists(self.ontology['setting cache path']):
            try:
                with io.open(self.ontology['setting cache path'], 'rb') as f:
                    self.node = pickle.load(f)
                # self.log.debug('configuration cache loaded from %s', self.ontology['setting cache path'])
            except KeyError:
                self.log.warning('failed loading configuration cache from %s', self.ontology['setting cache path'])
                self.node = None

        if self.node is None:
            self.node = {}
        if 'record' not in self.node:
            self.node['record'] = {}
        if 'instruction' not in self.node:
            self.node['instruction'] = {}
        if 'state' not in self.node:
            self.state = {}
        if 'order' not in self.node:
            self.node['order'] = []

    def load_module(self, module):
        self.log.debug('loading module %s', module['name'])
        if self.load_cached_file('module.json', module['absolute path']):
            for resource in self.module[module['name']]['include']:
                if 'path' in resource:
                    self.load_cached_file(resource['path'], module['absolute path'])

    def load_cached_file(self, path, base, report_missing=True):
        absolute = os.path.expanduser(os.path.expandvars(os.path.join(base, path)))
        key = hashlib.sha1(absolute.encode('utf8')).hexdigest()

        if key in self.instruction:
            instruction = self.instruction[key]
        else:
            self.instruction[key] = { 
                'base': base,
                'path': path,
                'absolute': absolute,
                'key': key,
                'name': path,
                'content': None,
                'content sha1': None
            }
            instruction = self.instruction[key]
            if os.path.isfile(instruction['absolute']):
                try:
                    with io.open(instruction['absolute'], 'rb') as f:
                        instruction['content'] = BytesIO(f.read())
                except OSError as e:
                    raise ConfigurationError('error reading configuration file {}'.format(instruction['absolute']))
                else:
                    instruction['content sha1'] = hashlib.sha1(instruction['content'].getvalue()).hexdigest()
            elif report_missing:
                self.log.debug('configuration file %s is missing', instruction['path'])
        return self.load_cached_record(instruction)

    def load_cached_record(self, instruction):
        if 'key' not in instruction and 'name' in instruction:
            instruction['key'] = hashlib.sha1(instruction['name'].encode('utf8')).hexdigest()

        key = instruction['key']
        if instruction['content'] is not None:
            instruction['content sha1'] = hashlib.sha1(instruction['content'].getvalue()).hexdigest()
        else:
            instruction['content sha1'] = None

        if instruction['content sha1'] is None:
            if key in self.record:
                del self.record[key]
                self.dirty = True
            return None

        if key in self.record:
            record = self.record[key]
        else:
            record = { 
                'key': key,
                'node': None,
                'cached sha1': None,
                'name': instruction['name'],
                'created': str(datetime.utcnow())
            }

        if record['cached sha1'] != instruction['content sha1']:
            try:
                record['node'] = json.loads(instruction['content'].getvalue().decode('utf8'))
            except ValueError as e:
                raise ConfigurationError('failed parsing json from {} because {}'.format(instruction['name'], str(e)))
            else:
                if record['node']:
                    record['cached sha1'] = instruction['content sha1']

            if record['cached sha1'] == instruction['content sha1']:
                self.record[key] = record
                self.dirty = True
                self.log.debug('refreshed %s', instruction['name'])

            elif record['cached sha1'] is not None:
                del self.record[key]
                self.dirty = True
                self.log.debug('dropped %s', instruction['name'])

        # merge into the state
        if record['cached sha1'] == instruction['content sha1']:
            difference = self.check_element(copy.deepcopy(record['node']))
            self.state = self.merge_element(self.state, difference)
            self.node['order'].append(record['cached sha1'])
        else:
            record = None

        return record

    def load_setting(self):
        self.log.debug('loading setting')

        change = { 'system': {} }

        # load repository setting into state
        relative = self.ontology['repository setting path']
        if self.load_cached_file(relative, self.home, False):
            change['system']['repository setting path'] = os.path.join(self.home, relative)
        elif self.load_cached_file(relative, self.system_home, False):
            change['system']['repository setting path'] = os.path.join(self.system_home, relative)

        # load host setting into state
        relative = self.ontology['host setting path']
        if self.load_cached_file(relative, self.home, False):
            change['system']['host setting path'] = os.path.join(self.home, relative)
        elif self.load_cached_file(relative, self.system_home, False):
            change['system']['host setting path'] = os.path.join(self.system_home, relative)

        # load user setting into state
        relative = self.ontology['user setting path']
        if self.load_cached_file(relative, self.home, False):
            change['system']['user setting path'] = os.path.join(self.home, relative)

        instruction = { 
            'name': 'system and user setting',
            'content': BytesIO(json.dumps(change, sort_keys=True).encode('utf8'))
        }
        self.load_cached_record(instruction)

    # before snapshot
    def apply_path_expansion(self):
        node = { 
            'enumeration': { 'volume': { 'element': {} }, 
            'path homology': { 'element': {} } }
        }

        for key, volume in self.state['enumeration']['volume']['element'].items():
            node['enumeration']['volume']['element'][key] = { 
                'path': os.path.expanduser(os.path.expandvars(volume['path'])),
                'abstract path': volume['path'] 
            }

        for key, homology in self.state['enumeration']['path homology']['element'].items():
            node['enumeration']['path homology']['element'][key] = { 
                'path': os.path.expanduser(os.path.expandvars(homology['path'])),
                'abstract path': homology['path'],
                'alternate': os.path.expanduser(os.path.expandvars(homology['alternate'])),
                'abstract alternate': homology['alternate'],
            }

        instruction = { 
            'name': 'path expansion',
            'content': BytesIO(json.dumps(node, sort_keys=True).encode('utf8'))
        }
        self.load_cached_record(instruction)

    def apply_version(self):
        node = { 'system': { }, 'interface': { } }

        # get git revision
        path = os.path.join(os.path.dirname(__file__), '.git/ORIG_HEAD')
        if os.path.isfile(path):
            with io.open(path, 'rb') as f:
                content = f.read().decode('utf8').strip()
                if content:
                    node['system']['tubo git revision'] = content

        # set the version string
        version = None
        if 'tubo major version' in self.state['system'] and 'tubo minor version' in self.state['system']:
            version = '{}.{}'.format(self.state['system']['tubo major version'], self.state['system']['tubo minor version'])
            if 'tubo git revision' in node['system']:
                version = '.'.join([version, node['system']['tubo git revision']])
            if 'tubo version comment' in self.state['system']:
                version = ' '.join([version, self.state['system']['tubo version comment']])

        for key, interface in self.state['interface'].items():
            if 'version' in interface['prototype'] and 'parameter' in interface['prototype']['version']:
                interface['prototype']['version']['parameter']['version'] = '%(prog)s {}'.format(version)
        node['system']['tubo version'] = version 

        # update interfaces with the version string
        for key, interface in self.state['interface'].items():
            if 'version' in interface['prototype'] and 'parameter' in interface['prototype']['version']:
                node['interface'][key] = {
                   'prototype': {
                        'version': {
                            'parameter': {
                                'version': '%(prog)s {}'.format(version)
                            }
                        }
                   } 
                }

        instruction = { 
            'name': 'version string',
            'content': BytesIO(json.dumps(node, sort_keys=True).encode('utf8'))
        }
        self.load_cached_record(instruction)

    # post snapshot will only run when creating a new snapshot
    def apply_volume_routing(self):
        node = { 'rule': {} }

        # temp location for each host
        name = 'rule/system/temp/location'
        rule = {
            'name': 'Temp location',
            'provide': ['temp path'],
            'branch': []
        }
        node['rule'][name] = rule
        for key in sorted(self.state['enumeration']['temporary workspace']['element'].keys()):
            temp = self.state['enumeration']['temporary workspace']['element'][key]
            branch = {
                'requires': [ 'host' ],
                'equal': { 'host': temp['host'] },
                'apply': [
                    { 'property': 'temp path', 'value': temp['path'] }
                ]
            }
            rule['branch'].append(branch)
        self.sort_branch_for_top(name, rule)

        # host name by volume
        name = 'rule/genealogy/volume/host'
        rule = {
            'name': 'Host from volume',
            'provide': [ 'host' ],
            'branch': []
        }
        node['rule'][name] = rule
        for key in sorted(self.state['enumeration']['volume']['element'].keys()):
            volume = self.state['enumeration']['volume']['element'][key]
            branch = {
                'requires': [ 'volume' ],
                'equal': { 'volume': key },
                'apply': [
                    { 'property': 'host', 'value': volume['host'] }
                ]
            }
            rule['branch'].append(branch)
        self.sort_branch_for_top(name, rule)

        # volume path by volume name and host
        name = 'rule/system/volume/location'
        rule = {
            'name': 'Volume location',
            'provide': ['volume path'],
            'branch': []
        }
        node['rule'][name] = rule
        for key in sorted(self.state['enumeration']['volume']['element'].keys()):
            volume = self.state['enumeration']['volume']['element'][key]
            branch = {
                'requires': ['volume', 'host'],
                'equal': {
                    'host': volume['host'], 
                    'volume': key
                },
                'apply': [
                    { 'property': 'volume path', 'value': volume['path'] }
                ]
            }
            rule['branch'].append(branch)
        self.sort_branch_for_top(name, rule)

        instruction = { 
            'name': 'volume routing',
            'content': BytesIO(json.dumps(node, sort_keys=True).encode('utf8'))
        }
        self.load_cached_record(instruction)

    def sanitize(self):
        # set the key attribute
        for name, section in self.section.items():
            if name in self.state and 'pad key' in section and section['pad key']:
                for key, item in self.state[name].items():
                    if item is not None:
                        item['key'] = key

        for name, section in self.section.items():
            if name in self.state and isinstance(self.state[name], dict) and 'handler' in section:
                section['handler'](self.state[name])

    def check(self):
        self.state = self.check_element(self.state)

    def sort(self):
        self.state = self.sort_element(self.state)

    def validate(self):
        # raise ConfigurationError('unknown host')
        for name, service in self.state['service'].items():
            if service is not None:
                for term in ['implementation', 'branch', 'match']:
                    if term not in service or not service[term]:
                        service['enabled'] = False
                        self.log.debug('service %s disabled because it is missing %s', name, term)
        # check that produce sections in services reference an existing service

    # always
    def apply_command_availability(self):
        node = { 'command': {} }
        for key, command in self.state['command'].items():
            node['command'][key] = { 'available': False }
            if 'binary' in command:
                node['command'][key]['executable'] = self.which(command['binary'], command)
                if node['command'][key]['executable'] is not None:
                    node['command'][key]['available'] = True

                if command['implementation'] == 'interpreted':
                    if not os.path.exists(command['script']):
                        node['command'][key]['available'] = False

                if command['implementation'] == 'java':
                    if 'jar' not in command or not os.path.exists(command['jar']):
                        node['command'][key]['available'] = False
        instruction = { 
            'name': 'command availability',
            'content': BytesIO(json.dumps(node, sort_keys=True).encode('utf8'))
        }
        self.load_cached_record(instruction)

    # after command line
    def apply_command_line(self, command):
        node = { 'system': { } }
        if 'host' in command and command['host'] is not None:
            node['system']['host'] = command['host']

        if 'language' in command and command['language'] is not None:
            node['system']['language'] = command['language']

        if node['system']:
            instruction = { 
                'name': 'version string',
                'content': BytesIO(json.dumps(node, sort_keys=True).encode('utf8'))
            }
            self.load_cached_record(instruction)

    def apply_default_host_and_language(self):
        node = { 'rule': {} }
        host = self.state['system']['host']
        language = self.state['system']['language']

        # default host
        name = 'rule/system/default/host'
        rule = {
            'name': 'Default host',
            'provide': ['host'],
            'branch': [
                { 'apply': [ { 'property': 'host', 'value': host } ]}
            ]
        }
        self.sort_branch_for_top(name, rule)
        node['rule'][name] = rule

        # default language
        name = 'rule/system/default/language'
        rule = {
            'name': 'Default language',
            'provide': ['language'],
            'branch': [
                { 'apply': [ { 'property': 'language', 'value': language } ] }
            ]
        }
        self.sort_branch_for_top(name, rule)
        node['rule'][name] = rule

        instruction = { 
            'name': 'default host and language',
            'content': BytesIO(json.dumps(node, sort_keys=True).encode('utf8'))
        }
        self.load_cached_record(instruction)

    def validate_system(self):
        if self.state['system']['host'] is None:
            raise ConfigurationError('unknown host')

        if self.state['system']['repository'] is None:
            raise ConfigurationError('unknown repository')

        if self.state['system']['repository'] not in self.state['repository']:
            raise ConfigurationError('undefined repository {}'.format(self.state['system']['repository']))

        if self.state['system']['language'] not in self.state['enumeration']['language']['element']:
            raise ConfigurationError('undefined language {}'.format(self.state['system']['language']))

    # sanitizing handlers
    def sanitize_archetype_node(self, node):
        for key, archetype in node.items():
            if 'keyword' not in archetype:
                archetype['keyword'] = key.replace(' ', '_')

            if 'name' not in archetype:
                archetype['name'] = key[0].upper() + key[1:]

    def sanitize_preset_node(self, node):
        pass

    def sanitize_service_node(self, node):
        pass

    def sanitize_enumeration_node(self, node):
        for name, space in node.items():
            prototype = self.make_enumeration_prototype()
            prototype = self.merge_element(prototype, space)
            if space['element'] is None:
                prototype['element'] = {}
            else:
                if isinstance(space['element'], dict):
                    prototype['element'] = {}
                    for key, element in space['element'].items():
                        default = copy.deepcopy(prototype['default'])
                        product = self.merge_element(default, element)
                        product['key'] = key
                        prototype['element'][key] = product

                elif isinstance(space['element'], list):
                    prototype['element'] = []
                    for element in space['element']:
                        if 'key' in element and element['key'] is not None:
                            default = copy.deepcopy(prototype['default'])
                            product = self.merge_element(default, element)
                            prototype['element'].append(product)
            node[name] = prototype

    def sanitize_namespace_node(self, node):
        for name, space in node.items():
            prototype = self.make_namespace_prototype()
            prototype = self.merge_element(prototype, space)
            if space['element'] is None:
                prototype['element'] = {}
            else:
                if isinstance(space['element'], dict):
                    prototype['element'] = {}
                    for key, element in space['element'].items():
                        default = copy.deepcopy(prototype['default'])
                        archetype = None if key not in self.state['archetype'] else copy.deepcopy(self.state['archetype'][key])
                        product = self.merge_element(default, self.merge_element(archetype, element))
                        product['key'] = key
                        prototype['element'][key] = product

                elif isinstance(space['element'], list):
                    prototype['element'] = []
                    for element in space['element']:
                        if 'key' in element and element['key'] is not None:
                            key = element['key']
                            default = copy.deepcopy(prototype['default'])
                            archetype = None if key not in self.state['archetype'] else copy.deepcopy(self.state['archetype'][key])
                            product = self.merge_element(default, self.merge_element(archetype, element))
                            prototype['element'].append(product)
            node[name] = prototype

    def sanitize_rule_node(self, node):
        for key, rule in node.items():
            if 'branch' not in rule:
                rule['branch'] = []
            else:
                for branch in rule['branch']:
                    if 'match' in branch and 'flags' not in branch['match']:
                        branch['match']['flags'] = re.UNICODE
                    if 'decode' in branch:
                        for c in branch['decode']:
                            if 'flags' not in c:
                                c['flags'] = re.UNICODE

    def sanitize_expression_node(self, node):
        for key, expression in node.items():
            if 'flags' not in expression:
                expression['flags'] = re.UNICODE

    def sanitize_command_node(self, node):
        for key, command in node.items():
            if 'implementation' not in command:
                command['implementation'] = 'binary'

            if 'style' not in command:
                command['style'] = 'POSIX'

            # standard output and standard error default to pipe
            if 'stderr' not in command: command['stderr'] = 'pipe'
            if 'stdout' not in command: command['stdout'] = 'pipe'

            # interpret the absolute location of the executable
            command['available'] = False

    def sanitize_repository_node(self, node):
        pass

    def sanitize_interface_node(self, node):
        for key, interface in node.items():
            for argument in interface['prototype'].values():
                if 'dest' in argument['parameter']:
                    destination = self.state['archetype'][argument['parameter']['dest']]
                    if destination['type'] == 'enum' and 'axis' in argument:
                        enumeration = self.state['enumeration'][destination['enumeration']]

                        if isinstance(enumeration['element'], dict):
                            argument['parameter']['choices'] = [ v[argument['axis']] for k,v in enumeration['element'].items() if argument['axis'] in v ]

                        elif isinstance(enumeration['element'], list):
                            argument['parameter']['choices'] = [ v[argument['axis']] for v in enumeration['element'] if argument['axis'] in v ]

    def sanitize_table_node(self, node):
        for key, table in node.items():
            if 'index' in table:
                for index in table['index']:
                    if 'unique' not in index:
                        index['unique'] = False
                    index['key'] = [ tuple(k) for k in index['key'] ]

    # recursive scans
    def merge_element(self, node, other):
        result = other
        if node is not None:
            result = node
            if other is not None:
                if isinstance(node, dict):
                    if isinstance(other, dict):
                        for k,v in other.items():
                            if k in result:
                                result[k] = self.merge_element(result[k], v)
                            else:
                                result[k] = v
                    else:
                        raise ConfigurationError('invalid configuration structure')

                elif isinstance(node, list):
                    if isinstance(other, list):
                        result.extend(other)
                    else:
                        raise ConfigurationError('invalid configuration structure')
                else:
                    result = other
        return result

    def check_element(self, element):
        result = None
        if isinstance(element, dict):
            if 'enabled' not in element or element['enabled']:
                if 'enabled' in element:
                    del element['enabled']

                for k in list(element.keys()):
                    element[k] = self.check_element(element[k])
                result = element

        elif isinstance(element, list):
            result = []
            for o in element:
                checked = self.check_element(o)
                if checked is not None:
                    result.append(checked)
        else:
            result = element

        return result

    def sort_element(self, element):
        if isinstance(element, dict):
            for k in list(element.keys()):
                element[k] = self.sort_element(element[k])

        elif isinstance(element, list):
            for index, o in enumerate(element):
                element[index] = self.sort_element(o)

            if all([isinstance(o, dict) for o in element]):
                if any(['order' in o for o in element]):
                    if not all(['order' in o for o in element]):
                        position = max([ o['order'] in o for o in element if 'order' in o ])
                        for o in element:
                             if 'order' not in o:
                                o['order'] = position
                                position += 1
                    element = sorted(element, key=lambda x: x['order'])
                    for index, o in enumerate(element):
                        o['order'] = 10 + index * 10

        return element

    def make_namespace_prototype(self):
        return copy.deepcopy(self.ontology['namespace default'])

    def make_enumeration_prototype(self):
        return copy.deepcopy(self.ontology['enumeration default'])

    def sort_branch_for_top(self, name, rule):
        if 'branch' in rule and rule['branch']:
            position = self.first_branch_position_in_rule(name)
            position -= len(rule['branch'])
            for branch in rule['branch']:
                branch['order'] = position
                position += 1

    def first_branch_position_in_rule(self, name):
        position = 0
        if name is not None and name in self.state['rule'] and 'branch' in self.state['rule'][name]:
            branch = self.state['rule'][name]['branch']
            if branch:
                position = [ b['order'] for b in branch if 'order' in b ]
                position = 0 if not position else min(position)
        return position

    def which(self, binary, command):
        def is_executable(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
        path = None
        fpath, fname = os.path.split(binary)
        if fpath:
            # a full path to the binary was given
            if is_executable(binary):
                path = binary
        else:
            if 'environment' in command:
                environment = command['environment']
            else:
                environment = os.environ

            # need to lookup in the path for the binary
            for p in environment['PATH'].split(os.pathsep):
                bpath = os.path.join(p, binary)
                if is_executable(bpath):
                    path = bpath
        return path

    def take_snapshot(self):
        return copy.deepcopy(self.state)

class Environment(object):
    def __init__(self):
        self.log = logging.getLogger('Environment')
        self.configuration = Configuration()
        self.state = {}
        self.token = threading.Condition()
        self.repository = None
        self.resolver = None
        self.queue = None
        self.rest = None
        for key, section in self.configuration.section.items():
            self.state[key] = {}

        # apply the interface value before the configuration is actually activated
        self.system['interface'] = self.configuration.state['system']['interface']

    def __str__(self):
        return self.host

    @property
    def home(self):
        return self.system['tubo home']

    @property
    def host(self):
        return self.system['host']

    @property
    def verbosity(self):
        return self.system['verbosity']

    @property
    def language(self):
        return self.system['language']

    @property
    def system(self):
        return self.state['system']

    @property
    def archetype(self):
        return self.state['archetype']

    @property
    def enumeration(self):
        return self.state['enumeration']

    @property
    def namespace(self):
        return self.state['namespace']

    @property
    def rule(self):
        return self.state['rule']

    @property
    def service(self):
        return self.state['service']

    @property
    def expression(self):
        return self.state['expression']

    @property
    def constant(self):
        return self.state['constant']

    @property
    def command(self):
        return self.state['command']

    @property
    def preset(self):
        return self.state['preset']

    @property
    def interface(self):
        return self.state['interface']

    @property
    def table(self):
        return self.state['table']

    def close(self):
        if self.repository: self.repository.close()
        self.log.debug('environment is shutting down')

    def ignite(self, instruction):
        self.configuration.ignite(instruction)
        self.load_configuration(self.configuration.take_snapshot())

        self.state['system'] = Ontology(self, 'ns/system/environment', self.state['system'])
        self.state['system'].interpret(instruction)
        self.state['system']['pid'] = os.getpid()
        self.state['system']['pgid'] = os.getpgid(0)

        logging.getLogger().setLevel(self.verbosity)

        self.resolver = Resolver(self)
        self.repository = Repository(self, self.state['repository'][self.system['repository']])

    def load_configuration(self, node):
        for key in self.configuration.section.keys():
            if key in node:
                section = node[key]
                if key == 'enumeration':
                    for k, e in section.items():
                        self.state[key][k] = Enumeration(self, e)

                elif key == 'namespace':
                    for k, e in section.items():
                        self.state[key][k] = PrototypeSpace(self, e)

                elif key == 'rule':
                    for k, e in section.items():
                        self.state[key][k] = Rule(self, e)

                elif key == 'expression':
                    for k, e in section.items():
                        self.state[key][k] = re.compile(e['definition'], e['flags'])

                else:
                    for k, e in section.items():
                        self.state[key][k] = e

    def prepare_to_write_to_remote_path(self, host, path, overwrite=False):
        from subprocess import Popen, PIPE
        def check_writable(host, path):
            p = Popen(['ssh', host, '[ -w "{}" ]'.format(path)])
            p.communicate()
            if p.returncode == 0: return True
            else: return False

        def check_directory_exist(host, path):
            p = Popen(['ssh', host, '[ -d "{}" ]'.format(path)])
            p.communicate()
            if p.returncode == 0: return True
            else: return False

        def check_inode_exist(host, path):
            p = Popen(['ssh', host, '[ -e "{}" ]'.format(path)])
            p.communicate()
            if p.returncode == 0: return True
            else: return False

        def create_directory(host, path):
            p = Popen(['ssh', host, 'mkdir', '-p', path])
            p.communicate()
            if p.returncode == 0: return True
            else: return False

        def check_permission(host, path):
            directory = os.path.dirname(path)
            writable = check_writable(host, directory)
            present = check_directory_exist(host, directory)

            if writable and present:
                # this hirarchy exists and is writable
                return directory

            elif not (writable or present):
                # try the next one up
                return check_permission(host, directory)

            elif present and not writable:
                # directory exists but it not writable
                raise PermissionDeniedError('{}:{}'.format(host, path))

        with self.token:
            available = check_permission(host, path)
            if check_inode_exist(host, path):
                if not overwrite: raise NoOverwriteError('{}:{}'.format(host,path))
            else:
                directory = os.path.dirname(path)
                if directory != available:
                    self.log.debug('creating directory %s:%s', host, directory)
                    create_directory(host, directory)

    def check_file_permission(self, path):
        directory = os.path.dirname(path)
        writable = os.access(directory, os.W_OK)
        present = os.path.exists(directory)

        if writable and present:
            # this hirarchy exists and is writable
            return directory

        elif not (writable or present):
            # try the next one up
            return self.check_file_permission(directory)

        elif present and not writable:
            # directory exists but it not writable
            raise PermissionDeniedError(path)

    def prepare_to_write_to_path(self, path, overwrite=False):
        def check_permission(path):
            directory = os.path.dirname(path)
            writable = os.access(directory, os.W_OK)
            present = os.path.exists(directory)

            if writable and present:
                # this hirarchy exists and is writable
                return directory

            elif not (writable or present):
                # try the next one up
                return check_permission(directory)

            elif present and not writable:
                # directory exists but it not writable
                raise PermissionDeniedError(path)

        with self.token:
            available = check_permission(path)
            if os.path.exists(path):
                if not overwrite: raise NoOverwriteError(path)
            else:
                directory = os.path.dirname(path)
                if directory != available:
                    self.log.debug('creating directory %s', directory)
                    os.makedirs(directory)

    def prepare_directory(self, directory):
        def check_permission(directory):
            writable = os.access(directory, os.W_OK)
            present = os.path.exists(directory)

            if writable and present:
                # this hirarchy exists and is writable
                return directory

            elif not (writable or present):
                # try the next one up
                return check_permission(os.path.dirname(directory))

            elif present and not writable:
                # directory exists but it not writable
                raise PermissionDeniedError(directory)

        with self.token:
            available = check_permission(directory)
            if available != directory:
               self.log.debug('creating directory %s', directory)
               os.makedirs(directory)

    def clean_directory(self, directory):
        with self.token:
            if directory and os.path.exists(directory):
                try:
                    os.removedirs(directory)
                except OSError: pass

    def clean_path(self, path):
        with self.token:
            if path and not os.path.exists(path):
                try:
                    os.removedirs(os.path.dirname(path))
                except OSError: pass

    def expand_home_id(self, ontology):
        result = False
        if ontology:
            if 'home id' in ontology:
                result = True

            elif 'home uri' in ontology:
                home = self.resolver.resolve(ontology['home uri'])
                if home is not None:
                    ontology['home id'] = home['head']['genealogy']['home id']
                    result = True
        return result

    def expand_home(self, ontology, context=None):
        result = False
        if ontology and 'home uri' in ontology:
            home = self.resolver.resolve(ontology['home uri'], None, context)
            if home is not None:
                ontology.overlay(home.genealogy)
                result = True
        return result

    def expand_knowledge(self, ontology, context=None):
        result = False
        if ontology and 'knowledge uri' in ontology:
            knowledge = self.resolver.resolve(ontology['knowledge uri'], None, context)
            if knowledge is not None:
                ontology.overlay(knowledge.body)
                result = True
        return result

    def default_json_handler(self, o):
        result = o
        if isinstance(o, datetime):
            result = o.isoformat()
        if isinstance(o, ObjectId):
            result = str(o)
        if isinstance(o, set):
            result = list(o)
        return result

    def to_json(self, node):
        # Can't use ensure_ascii=False because the logging library seems to break when fed utf8 with non ascii characters
        return json.dumps(node, sort_keys=True, indent=4, default=self.default_json_handler)

class Repository(object):
    def __init__(self, env, node):
        self.log = logging.getLogger('Repository')
        self.env = env
        self.node = node
        self.mongodb = Ontology(self.env, 'ns/system/mongodb', self.node['mongodb'])
        self._local = None
        self._connection = None

    def __str__(self):
        return str('{}:{}'.format(self.key))

    @property
    def valid(self):
        return self.connection is not None

    @property
    def key(self):
        return self.node['key']

    @property
    def host(self):
        return self.env.host

    @property
    def local(self):
        if self._local is None:
            self._local = {}
            for key, volume in self.volume.element.items():
                if volume.node['host'] == self.host:
                    self._local[key] = volume
        return self._local

    @property
    def volume(self):
        return self.env.enumeration['volume']

    @property
    def homology(self):
        return self.env.enumeration['path homology']

    @property
    def connection(self):
        if self._connection is None and 'mongodb url' in self.mongodb:
            try:
                self._connection = MongoClient(self.mongodb['mongodb url'])
            except pymongo.errors.ConnectionFailure as e:
                raise NetworkError('failed to establish connection with {} because {}'.format(self.mongodb['mongodb safe url'], e))
            else:
                self.log.debug('connection with %s established', self.mongodb['mongodb safe url'])
        return self._connection

    @property
    def database(self):
        if self.connection is not None:
            return self._connection[self.mongodb['database']]
        else:
            return None

    def close(self):
        if self._connection is not None:
            self.log.debug('closing mongodb connection to %s', self.mongodb['mongodb safe url'])
            self._connection.close()

    def resolve_inode(self, decoded):
        def resolve_homology(path):
            result = path
            if self.homology and 'alternate' in self.homology.synonym:
                for alternate, homology in self.homology.synonym['alternate'].items():
                    if os.path.commonprefix((alternate, path)) == alternate:
                        result = path.replace(alternate, homology.node['path'])
                        break
            return result

        location = None
        if decoded:
            # Normalize the directory
            # This will replace path fragments with canonic values
            decoded['dirname'] = resolve_homology(decoded['dirname'])

            # Check if the directory resides in a volume
            for key, volume in self.local.items():
                if os.path.commonprefix((volume.node['path'], decoded['dirname'])) == volume.node['path']:
                    decoded['volume'] = key
                    break

            # If a UMID was encoded in the name, infer the home id and media kind
            # This will also trigger rule.medium.resource.basename.parse
            if 'umid' in decoded:
                umid = Umid.decode(decoded['umid'])
                if umid:
                    decoded['media kind'] = umid.media_kind
                    decoded['home id'] = umid.home_id
                    decoded['nibble number'] = umid.nibble_number

            # Force kind inference
            decoded['kind']
            # Project a location ontology
            location = decoded.project('ns/service/genealogy')

            # Make the elements of the decoded onlology kernel elements of the result
            for k,v in decoded.items(): location[k] = v

            # Since dirname possibly changed when we normalized
            # remove the path so it can be inferred
            del location['path']
            location['path']

            # Set the host to local host
            location['host'] = self.host

            if 'home uri' not in location:
                location = None
                # raise UnresolvableResourceError('no decodable home uri')

            elif not self.env.expand_home(location):
                raise UnresolvableResourceError('unresolvable home uri {}'.format(location['home uri']))

        return location

    def rebuild_indexes(self, key, drop_on_restore=False):
        if key in self.env.table:
            table = self.env.table[key]
            collection = self.database[table['collection']]
            try:
                applied = [ i['name'] for i in table['index'] ]
                existing = collection.index_information()
                for index in existing.keys():
                    if index != '_id_' and (index in applied or drop_on_restore):
                        self.log.info('dropping index %s from %s', index, table['key'])
                        collection.drop_index(index)
            except pymongo.errors.OperationFailure as e:
                error = self.env.enumeration['mongodb error'].find(e.code)
                if error:
                    self.log.debug('mongodb error %d: %s', error.node['key'], error.node['name'])
                else:
                    self.log.debug('mongodb returned an operation failure code %s', e.code)
                    self.log.debug(str(e.details))

            for index in table['index']:
                if 'name' in index:
                    self.log.info('rebuilding index %s for %s', index['name'], table['key'])
                    collection.create_index(index['key'], name=index['name'], unique=index['unique'])
                else:
                    self.log.error('ignoring unnamed index for %s', table['key'])
        else:
            self.log.error('ignoring undefined table %s', key)
