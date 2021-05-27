# -*- coding: utf-8 -*-

import logging
import copy
import re
import unicodedata
import plistlib
import hashlib
import json

from error import *
from datetime import datetime

class Ontology(dict):
    def __init__(self, env, namespace, *args, **kw):
        dict.__init__(self, *args, **kw)
        self.log = logging.getLogger('Ontology')
        self.env = env

        #if namespace is None and dict.__contains__(self, 'dialect'):
        #    namespace = dict.__getitem__(self, 'dialect')

        if namespace is None:
            raise InvalidOntologyError('missing namespace declaration for ontology')

        elif namespace not in self.env.namespace:
            raise InvalidOntologyError('reference to undefined namespace {}'.format(namespace))

        self.namespace = self.env.namespace[namespace]
        #dict.__setitem__(self, 'dialect', namespace)

        for key in list(dict.keys(self)):
            element = dict.__getitem__(self, key)
            if element is None:
                # Remove any elements that are None 
                dict.__delitem__(self, key)
            else:
                prototype = self.namespace.find(key)
                if prototype is not None:
                    if prototype.type == 'object':
                        if prototype.plural:
                            for index, o in enumerate(element):
                                element[index] = Ontology(self.env, prototype.node['namespace'], o)
                        else:
                            dict.__setitem__(self, key, Ontology(self.env, prototype.node['namespace'], element))
                else:
                    self.log.debug('element %s is not declared in namespace %s', key, namespace)
        self.kernel = dict(self)
        self.dependency = {}

    def __str__(self):
        return str(self.kernel)

    def __setitem__(self, key, value):
        if key is not None:
            # Start by removing the concept to clean any implicit concepts
            # This also has the effect that setting a concept to None will effectively remove the concept,
            # so concepts can be assumed to not be None, but setting one to None removes it
            if dict.__contains__(self, key):
                self.__delitem__(key)

            # Concepts set by __setitem__ are considered kernel concepts
            if value is not None:
                # self.log.debug('set kernel concept %s', str({key:value}))
                self.kernel[key] = value
                dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        # Even if the key is not present
        # We remove it's dependencies
        if key in self.dependency:
            for d in self.dependency[key]:
                if dict.__contains__(self, d):
                    self.__delitem__(d)
            del self.dependency[key]

        # Silently ignore del for keys that are not present
        if dict.__contains__(self, key):
            # self.log.debug('semoved %s', str(key))
            if key in self.kernel:
                del self.kernel[key]
            dict.__delitem__(self, key)

    def __contains__(self, key):
        self._resolve(key)
        return dict.__contains__(self, key)

    def __missing__(self, key):
        self._resolve(key)
        return self.get(key)

    def _resolve(self, key):
        if not dict.__contains__(self, key):
            if key in self.namespace.deduction.dependency:
                for rule in self.namespace.deduction.dependency[key]:
                    for branch in rule.branch:

                        # Check preconditions are satisfied
                        taken = True
                        if 'requires' in branch:
                            unsatisfied = branch['requires'].difference(self)
                            while unsatisfied:
                                u = unsatisfied.pop()
                                self._resolve(u)
                                if dict.__contains__(self, u):
                                    unsatisfied = branch['requires'].difference(self)
                                else: unsatisfied = None
                            if not branch['requires'].issubset(self):
                                taken = False
                        taken = taken and ('equal' not in branch or all((dict.__contains__(self, k) and dict.__getitem__(self, k) == v) for k,v in branch['equal'].items()))
                        taken = taken and ('match' not in branch or branch['match']['pattern'].match(dict.__getitem__(self, branch['match']['property'])))

                        if taken:
                            if 'apply' in branch:
                                for x in branch['apply']:
                                    if not dict.__contains__(self, x['property']):
                                        if 'digest' in x and 'algorithm' in x:
                                            if x['algorithm'] == 'sha1':
                                                dict.__setitem__(self, x['property'], hashlib.sha1(self[x['digest']].encode('utf-8')).hexdigest())
                                            elif x['algorithm'] == 'umid':
                                                dict.__setitem__(self, x['property'], Umid(*[self[i] for i in x['digest']]).code)
                                            elif x['algorithm'] == 'length':
                                                dict.__setitem__(self, x['property'], len(self[x['digest']]))
                                            elif x['algorithm'] == 'hide':
                                                dict.__setitem__(self, x['property'], '{0:{0}>{1}}'.format('*', len(self[x['digest']])))

                                        if 'reference' in x:
                                            if 'member' in x:
                                                prototype = self.namespace.find(x['property'])
                                                if prototype:
                                                    try:
                                                        dict.__setitem__(self, x['property'], getattr(self[x['reference']], x['member']))
                                                    except AttributeError as e:
                                                        self.log.error(u'Failed to locate member %s for %s: %s', x['member'], x['property'], e)
                                            elif 'datetime format' in x:
                                                prototype = self.namespace.find(x['property'])
                                                if prototype:
                                                    dict.__setitem__(self, x['property'], prototype.cast(self[x['reference']].strftime(x['datetime format'])))
                                            else:
                                                dict.__setitem__(self, x['property'], self[x['reference']])
                                        if 'format' in x:
                                            dict.__setitem__(self, x['property'], x['format'].format(**self))
                                        elif 'value' in x:
                                            dict.__setitem__(self, x['property'], x['value'])

                            if 'decode' in branch:
                                for x in branch['decode']:
                                    match = x['pattern'].search(dict.__getitem__(self, x['property']))
                                    if match is not None:
                                        parsed = match.groupdict()
                                        for synonym,raw in parsed.items():
                                            k,v = self.namespace.decode(synonym, raw)
                                            if k is not None and v is not None:
                                                dict.__setitem__(self, k, v)

                            # Mark all the atom the rule provides as depending on the requirements
                            # This means removing the requirement also removes the dependent atom
                            if 'requires' in branch:
                                for req in branch['requires']:
                                    if req not in self.dependency:
                                        self.dependency[req] = copy.deepcopy(rule.provide)
                                    else:
                                        self.dependency[req] = self.dependency[req].union(rule.provide)
                            break

    @classmethod
    def clone(cls, other):
        o = cls(other.env, other.namespace.key)
        for key,value in other.kernel.items():
            prototype = other.namespace.find(key)
            if prototype is not None:
                if prototype.type == 'object':
                    if prototype.plural:
                        # a list of references to embedded ontologies
                        o[key] = []
                        for e in value: o[key].append(Ontology.clone(e))

                    else:
                        # a reference to an embedded ontology
                        o[key] = Ontology.clone(value)
                else:
                    if prototype.plural:
                        o[key] = []
                        for e in value: o[key].append(e)
                    else:
                        o[key] = value
        return o

    @property
    def node(self):
        return self.kernel

    def touch(self, keys=None, recursive=False):
        if keys is None: k = list(self.namespace.element.keys())
        else: k = keys
        for key in k:
            if self[key] is not None and recursive:
                prototype = self.namespace.find(key)
                if prototype is not None:
                    if prototype.type == 'object':
                        if prototype.plural:
                            for e in self[key]:
                                e.touch(keys, recusrive)
                        else:
                            self[key].touch(keys, recursive)

    def match(self, fact):
        result =  all((k in self and self[k] == v) for k,v in fact.items())
        return result

    def project(self, namespace):
        projection = Ontology(self.env, namespace)
        for key, value in self.kernel.items():
            prototype = projection.namespace.find(key)
            if prototype is not None:
                if prototype.type == 'object':
                    if prototype.plural:
                        projection[key] = [ Ontology.clone(o) for o in value ]
                    else:
                        projection[key] = Ontology.clone(value)
                else:
                    if prototype.plural:
                        projection[key] = [ o for o in value ]
                    else:
                        projection[key] = value
        #dict.__setitem__(o, 'dialect', o.namespace.key)
        return projection

    def clear(self):
        self.kernel.clear()
        self.dependency.clear()
        dict.clear(self)

    def coalesce(self, source, target):
        k,v = self.namespace.merge(target, self[target], self[source])
        self.__setitem__(k, v)

    def merge(self, key, value):
        if key:
            k,v = self.namespace.merge(key, self[key], value)
            self.__setitem__(k, v)

    def overlay(self, mapping):
        for k,v in mapping.items():
            self.merge(k,v)
        #dict.__setitem__(self, 'dialect', self.namespace.key)

    def decode(self, synonym, value, axis=None):
        if synonym and value is not None:
            k,v = self.namespace.decode(synonym, value, axis)
            self.__setitem__(k, v)

    def interpret(self, mapping, axis=None):
        if mapping is not None:
            if not isinstance(mapping, dict):
                self.log.debug('failed to decode %s because the mapping provided is not a dictionary', mapping)
            else:
                for k,v in mapping.items():
                    self.decode(k,v, axis)
            self.normalize()
            #dict.__setitem__(self, 'dialect', self.namespace.key)

    def absorb(self, object, allowed, immutable=[]):
        if object and allowed:
            considered = [ e for e in allowed if e in object and object[e] is not None ]
            mutable = []

            # check for mutability
            for element in considered:
                if element in immutable and self[element] is not None and self[element] != object[element]:
                    raise InconsistencyError('value {} for {} is different than immutable {}'.format(object[element], element, self[element]))
                else:
                    mutable.append(element)

            for element in mutable:
                if self[element] is not None and self[element] != object[element]:
                    self.log.debug('value for %s changed from %s to %s', element, self[element], object[element])
                self[element] = object[element]

    def normalize(self):
        for action in self.namespace.node['normalize']:
            # coalescing several elements into one        
            if action['action'] == 'coalesce':
                target = action['target']
                for source in action['source']:
                    if source in self:
                        self.coalesce(source, target)
                        if not source == target:
                            self.__delitem__(source)

            # complementing embed elements 
            elif action['action'] == 'complement':
                if action['element'] in self:
                    prototype = self.namespace.find(action['element'])
                    if prototype:
                        if prototype.type == 'object':
                            if prototype.plural:
                                for e in self[action['element']]:
                                    for k,v in action['extension'].items():
                                        e[k] = v
                            else:
                                for k,v in action['extension'].items():
                                    self[action['element']][k] = v

        # recursively normalize embedded ontologies
        for key in dict.keys(self):
            element = dict.__getitem__(self, key)
            if element is not None:
                prototype = self.namespace.find(key)
                if prototype is not None:
                    if prototype.type == 'object':
                        if not prototype.plural:
                            # a reference to an embedded ontology
                            element.normalize()

                        else:
                            # a list of references to embedded ontologies
                            for e in element:
                                e.normalize()
        self.sort()

    def sort(self):
        def sort_element(element):
            if isinstance(element, dict):
                for k in list(element.keys()):
                    element[k] = sort_element(element[k])

            elif isinstance(element, list):
                for index, o in enumerate(element):
                    element[index] = sort_element(o)

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
        sort_element(self)

class Document(Ontology):
    def __init__(self, env, namespace, record, *args, **kw):
        Ontology.__init__(self, env, 'ns/service/document')
        body = None
        if isinstance(record, dict):
            for k,v in record.items():
                if k not in ['head', 'body']:
                    self[k] = v

            if 'head' in record and isinstance(record['head'], dict):
                self['head'] = Ontology(self.env, 'ns/service/document/head', record['head'])

            if 'body' in record and isinstance(record['body'], dict):
                body = record['body']

        if not self.head:
            self['head'] = Ontology(self.env, 'ns/service/document/head')

        if namespace is not None:
            self.head['namespace'] = namespace

        if 'genealogy' not in self.head:
            self.head['genealogy'] = Ontology(self.env, 'ns/service/genealogy')

        if 'alternate' not in self.head:
            self.head['alternate'] = []

        if 'canonical' not in self.head:
            self.head['canonical'] = None

        if 'created' not in self.head:
            self.head['created'] = None

        if 'modified' not in self.head:
            self.head['modified'] = None

        if body is None:
            self['body'] = Ontology(self.env, self.head['namespace'])
        else:
            self['body'] = Ontology(self.env, self.head['namespace'], body)

    def __str__(self):
        return str(self.canonical)

    @property
    def head(self):
        return self['head']

    @property
    def body(self):
        return self['body']

    @property
    def genealogy(self):
        return self.head['genealogy']

    @property
    def alternate(self):
        return self.head['alternate']

    @property
    def canonical(self):
        return self.head['canonical']

    @canonical.setter
    def canonical(self, value):
        self.head['canonical'] = value

    @property
    def created(self):
        return self.head['created']

    @created.setter
    def created(self, value):
        self.head['created'] = value

    @property
    def modified(self):
        return self.head['modified']

    @modified.setter
    def modified(self, value):
        self.head['modified'] = value

class Space(object):
    def __init__(self, env, node):
        self.log = logging.getLogger('Ontology')
        self.env = env
        self._element = None
        self._synonym = None
        self._deduction = None
        self.node = node

    def __str__(self):
        return self.key

    @property
    def key(self):
        return self.node['key']

    @property
    def element(self):
        if self._element is None:
            self._element = {}
            buffer = None
            if isinstance(self.node['element'], dict):
                buffer = list(self.node['element'].values())

            elif isinstance(self.node['element'], list):
                buffer = self.node['element']

            if buffer is not None:
                for element in buffer:
                    self._element[element['key']] = self._make_element(element)
        return self._element

    @property
    def synonym(self):
        if self._synonym is None:
            self._synonym = {}
            if 'synonym' in self.node:
                for synonym in self.node['synonym']:
                    self._synonym[synonym] = {}
                    for e in self.element.values():
                        if synonym in e.node and e.node[synonym] is not None:
                            self._synonym[synonym][e.node[synonym]] = e
        return self._synonym

    @property
    def deduction(self):
        if self._deduction is None:
            self._deduction = Deduction(self.env, self.node)
        return self._deduction

    @property
    def default(self):
        return self.node['default']

    def contains(self, key):
        return key is not None and key in self.element

    def find(self, key):
        # returns an element by key
        if key is not None and key in self.element:
            return self.element[key]
        else: return None

    def search(self, synonym, axis=None):
        element = None
        # returns an element by synonym
        if synonym is not None and 'synonym' in self.node:
            if axis is None:
                for x in self.node['synonym']:
                    if synonym in self.synonym[x]:
                        element = self.synonym[x][synonym]
                        break
            elif axis in self.synonym and synonym in self.synonym[axis]:
                element = self.synonym[axis][synonym]
        return element

    def parse(self, synonym, axis=None):
        # returns the key by synonym
        element = self.search(synonym, axis)
        if element is not None: return element.key
        else: return None

    def format(self, key):
        # returns an element name by key
        element = self.find(key)
        if element is not None: return element.name
        else: return None

    def map(self, key, synonym):
        if key is not None and synonym is not None and key in self.element:
            e = self.element[key]
            self.synonym[synonym] = e

    def add(self, key, node):
        if key is not None and node is not None:
            self.node['element'][key] = node
            self._element = None
            self._synonym = None

class Element(object):
    def __init__(self, space, node):
        self.log = logging.getLogger('Ontology')
        self.space = space
        self.node = node

    @property
    def env(self):
        return self.space.env

    @property
    def default(self):
        return self.space.default

    @property
    def key(self):
        return self.node['key']

    @property
    def name(self):
        return self.node['name']

class PrototypeSpace(Space):
    def __init__(self, env, node):
        Space.__init__(self, env, node)
        #self.node['element']['dialect'] = None

    def validate(self):
        for element in self.element.values():
            if element.type == 'object' and element.plural:
                if 'single' not in element.node:
                    self.log.debug('plural embed element %s in namespace %s is missing a single definition', element.key, self.key)

                elif self.find(element.node['single']) is None:
                    self.log.debug('single element %s for plural embed element %s in namespace %s is missing', element.node['single'], element.key, self.key)

    def _make_element(self, node):
        return Prototype(self, node)

    def merge(self, key, left, right):
        prototype = self.find(key)
        if prototype:
            return (prototype.key, prototype.merge(left, right))
        else:
            return (None, None)

    def decode(self, synonym, value, axis=None):
        prototype = self.search(synonym, axis)
        if prototype:
            return (prototype.key, prototype.cast(value, axis))
        else:
            return (None, None)

    def similar(self, first, second):
        result = False
        if first and second and self.node['similarity']:
            for key in self.node['similarity']:
                result = all([ w in first and w in second and first[w] == second[w] for w in key ])

                # if one of the key sets resolves to True no need to continue
                if result: break
        return result

class Prototype(Element):
    def __init__(self, space, node):
        Element.__init__(self, space, node)
        self.node = node

        # find the cast, format and merge functions
        c = getattr(self, '_cast_{}'.format(self.type), None) or (lambda x,y: x)
        f = getattr(self, '_format_{}'.format(self.type), None) or (lambda x: x)
        s = getattr(self, '_similar_{}'.format(self.type), None) or (lambda x,y: x == y)

        self._similar = s

        if self.plural:
            self._format = lambda x: self._format_list(x, f)
            self._cast = lambda x,y: self._cast_list(x, c, y)
            self.merge = self._merge_list
        else:
            self._cast = c
            self._format = f
            if self.type == 'object':
                self.merge = self._merge_object
            else:
                self.merge = self._merge_scalar

        if not self.node['decode']:
            self._cast = lambda x,y: x

    @property
    def type(self):
        return self.node['type']

    @property
    def plural(self):
        return self.node['plural']

    @property
    def keyword(self):
        return self.node['keyword']

    def cast(self, value, axis=None):
        if value is not None:
            return self._cast(value, axis)
        else:
            return None

    def format(self, value):
        if value is not None:
            return self._format(value)
        else:
            return None

    def similar(self, first, second):
        result = False

        if first is None:
            if second is None: result = True

        elif second is not None:
            result = self._similar(first, second)
        return result

    def _wrap(self, value):
        result = value
        if len(value) > self.env.format['wrap width']:
            lines = textwrap.wrap(value, self.env.format['wrap width'])
            result = self.env.format['indent'].join(lines)
        return result

    def _format_byte_as_iec_60027_2(self, value):
        p = 0
        v = float(value)
        while v > 1024.0 and p < 4:
            p += 1
            v /= 1024.0
        return '{:.2f} {1}'.format(v, self.env.enumeration['binary iec 60027 2'].format(p))

    def _format_bit_as_si(self, value):
        p = 0
        v = float(value)
        while v > 1000.0 and p < 4:
            p += 1
            v /= 1000.0
        return '{:.2f} {1}'.format(v, self.env.enumeration['decimal si'].format(p))

    def _format_enum(self, value):
        return self.env.enumeration[self.node['enumeration']].format(value)

    def _format_float(self, value):
        return '{:.3f}'.format(value)

    def _format_integer(self, value):
        result = str(value)
        if 'format' in self.node:
            if self.node['format'] == 'bitrate':
                result = '{}/s'.format(self._format_bit_as_si(value))

            elif self.node['format'] == 'millisecond':
                result =  self._format_timecode(value)

            elif self.node['format'] == 'byte':
                result = self._format_byte_as_iec_60027_2(value)

            elif self.node['format'] == 'bit':
                result = '{} bit'.format(value)

            elif self.node['format'] == 'frequency':
                result = '{} Hz'.format(value)

            elif self.node['format'] == 'pixel':
                result = '{} px'.format(value)

        return result

    def _format_boolean(self, value):
        if value is True: return 'yes'
        else: return 'no'

    def _format_plist(self, value):
        return str(value)

    def _format_date(self, value):
        return str(value)

    def _format_list(self, value, formatter):
        if value:
            return ', '.join([ formatter(v) for v in value ])
        else:
            return None

    def _format_string(self, value):
        return value

    def _cast_enum(self, value, axis=None):
        return self.env.enumeration[self.node['enumeration']].parse(value)

    def _cast_integer(self, value, axis=None):
        result = None
        try:
            result = int(value)
        except ValueError:
            self.log.error('failed to decode value %s as integer for %s', value, self.key)
        return result

    def _cast_float(self, value, axis=None):
        result = None
        try:
            result = float(value)
        except ValueError:
            self.log.error('Failed to decode value %s as float for %s', value, self.key)
        return result

    def _cast_string(self, value, axis=None):
        result = value.strip()
        result = str(result)
        if result:
            if self.node['simplify']:
                result = self._simplify(result)
        else:
            result = None
        return result

    def _cast_date(self, value, axis=None):
        result = None
        if 'format' in self.node:
            if self.node['format'] == 'unix time':
                result = self._cast_integer(value)
                if result is not None:
                    result = datetime.utcfromtimestamp(result)

            elif self.node['format'] == 'short':
                match = self.env.expression['short datetime'].search(value)
                if match:
                    parsed = dict([(k, int(v)) for k,v in match.groupdict().items() if v is not None])
                    try:
                        parsed['year'] += 2000
                        if parsed['year'] > datetime.utcnow().year:
                            parsed['year'] = parsed['year'] - 100

                        result = datetime(**parsed)
                    except (TypeError, ValueError):
                        self.log.debug('failed to decode value %s as datetime for %s', value, self.key)
                else:
                    self.log.debug('failed to parse value %s as datetime for %s', value, self.key)

            elif self.node['format'] == 'long':
                match = self.env.expression['long datetime'].search(value)
                if match:
                    parsed = dict([(k, int(v)) for k,v in match.groupdict().items() if v is not None])
                    try:
                        result = datetime(**parsed)
                    except (TypeError, ValueError):
                        self.log.debug('failed to decode value %s as datetime for %s', value, self.key)
                else:
                    self.log.debug('failed to parse value %s as datetime for %s', value, self.key)
        else:

            # Datetime conversion, must have at least a Year, Month and Day.
            # If Year is present but Month and Day are missing they are set to 1
            match = self.env.expression['full utc datetime'].search(value)
            if match:
                parsed = dict([(k, int(v)) for k,v in match.groupdict().items() if k != 'tzinfo' and v is not None])
                if 'month' not in parsed:
                    parsed['month'] = 1
                if 'day' not in parsed:
                    parsed['day'] = 1
                try:
                    result = datetime(**parsed)
                except (TypeError, ValueError):
                    self.log.debug('failed to decode value %s as datetime for %s', value, self.key)
            else:
                self.log.debug('failed to parse value %s as datetime for %s', value, self.key)
        return result

    def _cast_boolean(self, value, axis=None):
        result = False
        if type(value) is bool:
            result = value
        elif self.env.expression['true value'].search(value) is not None:
            result = True
        return result

    def _cast_plist(self, value, axis=None):
        # Clean and parse plist into a dictionary
        result = value
        result = self.env.expression['clean xml'].sub('', result).strip()
        try:
            result = plistlib.readPlistFromString(result.encode('utf-8'))
        except Exception as e:
            self.log.error('Failed to parse plist for %s', self.key)
            result = None
        return result

    def _cast_list(self, value, caster, axis=None):
        result = None

        # cast result elements
        result = [ caster(v, axis) for v in value ]

        # strip None elements
        if result: result = [ v for v in result if v is not None ]

        # empty result becomes None
        if not result: result = None

        return result

    def _cast_object(self, value, axis=None):
        if 'parse' in self.node and isinstance(value, str):
            if self.node['parse'] == 'json':
                try:
                    value = json.loads(value)
                except ValueError as error:
                    self.log.error('failed parsing json from %s because %s', value, str(error))

        result = Ontology(self.env, self.node['namespace'])
        result.interpret(value, axis)
        if not result:
            result = None
        return result

    def _similar_object(self, first, second):
        result = False
        namespace = self.env.namespace[self.node['namespace']]
        if namespace:
            result = namespace.similar(first, second)
        else:
            self.log.debug('reference to an undeclared namespace %s', self.node['namespace'])

        return result

    def _merge_scalar(self, left, right):
        if right is not None: return right
        return left

    def _merge_object(self, left, right):
        result = left
        if right is not None:
            if result is None:
                result = Ontology.clone(right)
            else:
                result.overlay(right)
        return result

    def _merge_list(self, left, right):
        if left is None: result = []
        else: result = left

        for next in right:
            taken = False
            for i,element in enumerate(result):
                if self.similar(next, element):
                    taken = True
                    if self.type == 'object':
                        # merge the two elements
                        result[i] = self.space.find(self.node['single']).merge(element, next)
                    else:
                        result[i] = self.merge(element, next)

            if not taken:
                # the new element does not match any existing
                if self.type == 'object':
                    result.append(Ontology.clone(next))
                else:
                    result.append(next)
        return result

    def _remove_accents(self, value):
        result = None
        if value:
            nkfd = unicodedata.normalize('NFKD', value)
            result = self.env.constant['empty string'].join([c for c in nkfd if not unicodedata.combining(c)])
        return result

    def _simplify(self, value):
        result = None
        if value:
            v = self.env.expression['whitespace'].sub(self.env.constant['space'], value).strip()
            if v:
                result = self.env.expression['characters to exclude from filename'].sub(self.env.constant['empty string'], v)
                if not result:
                    result = v
                    result = result.replace('?', 'question mark')
                    result = result.replace('*', 'asterisk')
                    result = result.replace('.', 'period')
                    result = result.replace(':', 'colon')
                result = self._remove_accents(result)
                result = result.lower()
        return result

class Enumeration(Space):
    def __init__(self, env, node):
        Space.__init__(self, env, node)

    def _make_element(self, node):
        return Enumerator(self, node)

class Enumerator(Element):
    def __init__(self, space, node):
        Element.__init__(self, space, node)

class Deduction(object):
    def __init__(self, env, node):
        self.log = logging.getLogger('Ontology')
        self.env = env
        self.node = node
        self._rule = None
        self._dependency = None

    @property
    def rule(self):
        if self._rule is None:
            self.reload()
        return self._rule

    @property
    def dependency(self):
        if self._dependency is None:
            self.reload()
        return self._dependency

    def reload(self):
        self._rule = {}
        self._dependency = {}
        for key in self.node['rule']:
            rule = self.env.rule[key]
            self.rule[key] = rule
            for ref in rule.provide:
                if ref not in self.dependency:
                    self.dependency[ref] = []
                self.dependency[ref].append(rule)

    def find(self, key):
        if key in self.rule:
            return self.rule[key]
        else:
            return None

class Rule(object):
    def __init__(self, env, node):
        self.log = logging.getLogger('Rule')
        self.env = env
        self.node = node

        if 'provide' in self.node:
            self.node['provide'] = set(self.node['provide'])

        if 'branch' not in self.node:
            self.node['branch'] = []

        for branch in self.node['branch']:
            if 'requires' in branch:
                branch['requires'] = set(branch['requires'])
            try:
                if 'match' in branch:
                    branch['match']['pattern'] = re.compile(branch['match']['expression'], branch['match']['flags'])

                if 'decode' in branch:
                    for p in branch['decode']:
                        p['pattern'] = re.compile(p['expression'], p['flags'])
            except Exception as e:
                self.log.error('Failed to load branch for rule %s', self.node['key'])
                self.log.debug(str(e))

    def __str__(self):
        return self.node['key']

    @property
    def valid(self):
        return True

    @property
    def provide(self):
        return self.node['provide']

    @property
    def branch(self):
        return self.node['branch']

class Umid(object):
    def __init__(self, home_id=None, media_kind=None, nibble_number=None):
        self._home_id = home_id
        self._media_kind = media_kind
        self._nibble_number = None
        self.nibble_number = nibble_number

    @classmethod
    def decode(cls, code):
        umid = cls()
        umid.code = code
        if umid.code is not None: return umid
        else: return None

    @classmethod
    def _checksum(cls, string):
        digits = [int(x,16) for x in string]
        return (sum(digits[::-2]) + sum([sum(divmod(3*d, 16)) for d in digits[-2::-2]])) % 16

    @classmethod
    def _check_digit(cls, string):
        d = Umid._checksum(string + '0')
        if d != 0: d = 16 - d
        return '{:x}'.format(d)

    @classmethod
    def verify(cls, string):
        return string is not None and Umid._checksum(string) == 0

    def _parse(self):
        self._media_kind = int(self._code[0:2], 16)
        self._nibble_number = int(self._code[2:3], 16)
        self._home_id = int(self._code[3:13], 16)

    @property
    def media_kind(self):
        if self._media_kind is None and self._code is not None:
            self._parse()
        return self._media_kind

    @media_kind.setter
    def media_kind(self, value):
        self._media_kind = value
        self._code = None

    @property
    def home_id(self):
        if self._home_id is None and self._code is not None:
            self._parse()
        return self._home_id

    @home_id.setter
    def home_id(self, value):
        self._home_id = value
        self._code = None

    @property
    def nibble_number(self):
        if self._nibble_number is None and self._code is not None:
            self._parse()
        if self._nibble_number != 0:
            return self._nibble_number
        else:
            return None

    @nibble_number.setter
    def nibble_number(self, value):
        if value is None: value = 0
        self._nibble_number = value
        self._code = None

    @property
    def code(self):
        if self._code is None and self._media_kind is not None and self._home_id is not None:
            code = '{:>02x}{:>01x}{:>010x}'.format(self._media_kind, self._nibble_number, self._home_id)
            self._code = '{}{}'.format(code, Umid._check_digit(code))
        return self._code

    @code.setter
    def code(self, value):
        self._home_id = None
        self._nibble_number = None
        self._media_kind = None
        if Umid.verify(value):
            self._code = value
        else:
            raise UmidValidationError('incorrect umid checksum {}'.format(value))
