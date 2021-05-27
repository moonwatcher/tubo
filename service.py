 # -*- coding: utf-8 -*-

import os
import re
import uuid
import logging
import json
import urllib.request, urllib.parse, urllib.error
import urllib.parse
import threading
import random

from datetime import datetime
from ontology import Ontology, Document
from io import StringIO
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from http.client import BadStatusLine
from pymongo.errors import DuplicateKeyError
from error import *

split_class = lambda x: (x[0:x.rfind('.')], x[x.rfind('.') + 1:])

class Resolver(object):
    def __init__(self, env):
        self.log = logging.getLogger('Resolver')
        self.env = env
        self.handlers = {}
        self.lock = threading.RLock()

        for service in self.env.service.values():
            self.register(service)
        self.log.debug('resolver loaded with modules %s', ', '.join(self.handlers.keys()))

    def register(self, service):
        if service is not None:
            implementation = service['implementation']
            implementation['module'], implementation['class name']  = split_class(implementation['class'])
            try:
                handler_module = __import__(implementation['module'], fromlist=[implementation['class name']])
                handler_class = getattr(handler_module, implementation['class name'])
                handler_instance = handler_class(self, service)
            except ImportError as e:
                self.log.error('no module named %s found when attempting to register service %s', implementation['module'], service['key'])
                self.log.debug(e)
            except AttributeError as e:
                self.log.error('module %s does not define %s when attempting to register service %s', implementation['module'], implementation['class name'], service['key'])
                self.log.debug(e)
            except Exception as e:
                self.log.error('%s %s', e, type(e))
            else:
                self.handlers[service['key']] = handler_instance

    @property
    def repository(self):
        return self.env.repository

    def resolve(self, uri, location=None, context=None):
        result = None
        if uri is not None:
            p = urllib.parse.urlparse(uri)
            for handler in self.handlers.values():
                if handler.handles(p.path):
                    result = handler.resolve(p.path, location, context)
                    break
        return result

    def remove(self, uri):
        if uri is not None:
            parsed = urllib.parse.urlparse(uri)
            for handler in self.handlers.values():
                if handler.handles(parsed.path):
                    result = handler.remove(parsed.path)
                    break

    def save(self, node):
        if node:
            if 'head' in node:
                head = node['head']
                if 'canonical' in head and head['canonical']:
                    uri = head['canonical']
                    for handler in self.handlers.values():
                        match = handler.handles(uri)
                        if match is not None:
                            handler.save(node)
                            break
                else:
                    self.log.error('refusing to save record with missing canonical address\n{}'.format(self.env.to_json(head)))            
            else:
                self.log.error('refusing to save a headless document')
        else:
            self.log.error('refusing to save an empty document')

    def issue(self, name):
        result = None

        if name == 'local':
            result = str(uuid.uuid4())
        else:
            issued = self.repository.database.counters.find_and_modify(
                query={'_id':name},
                update={'$inc':{'next':1}, '$set':{'modified':datetime.utcnow()}},
                new=True,
                upsert=True
            )
            if issued is not None:
                self.log.debug('new key %d issued from pool %s', issued['next'], issued['_id'])
                result = int(issued['next'])
        return result

    def browse(self, name, limit=None, skip=None):
        buffer = None
        if name in self.env.table:
            buffer = []
            table = self.env.table[name]
            collection = self.repository.database[table['collection']]
            cursor = collection.find({}, {'head':True})
            if limit is not None:
                cursor.limit(limit)
            if skip is not None:
                cursor.skip(skip)

            for document in cursor:
                buffer.append(Ontology(self.env, 'ns/service/document/head', document['head']))
        return buffer

class Query(object):
    def __init__(self, handler, uri, location, context, branch, match, base):
        self.log = logging.getLogger('Resolver')
        self.handler = handler
        self.node = {
            'uri': uri,
            'location': location,
            'context': context,
            'branch': branch,
            'match': match,
            'sync': context is not None and context['task execution']['task']['sync'],
            'genealogy': Ontology(self.env, 'ns/service/genealogy'),
            'immutable': [],
            'query parameter': None,
            'sources': [],
            'entries': [],
            'result': None,
            'remote url': None,
            'persistent': None,
        }

        if 'api key' in self.handler.node:
            self.genealogy['api key'] = random.choice(self.handler.node['api key'])
            # self.log.debug('api key for {} picked for service {}.'.format(self.genealogy['api key'], self.handler.name))

        self.genealogy.absorb(self.handler.node, ['username'])
        self.immutable.extend(('api key', 'username'))

        if base:
            self.genealogy.absorb(base, base)
            self.immutable.extend(base.keys())

    @property
    def env(self):
        return self.handler.env

    @property
    def uri(self):
        return self.node['uri']

    @property
    def location(self):
        return self.node['location']

    @location.setter
    def location(self, value):
        self.node['location'] = value

    @property
    def context(self):
        return self.node['context']

    @property
    def branch(self):
        return self.node['branch']

    @property
    def match(self):
        return self.node['match']

    @property
    def index(self):
        return self.branch['index']

    @property
    def persistent(self):
        if self.node['persistent'] is None:
            return self.branch['persistent']
        else:
            return self.node['persistent']

    @persistent.setter
    def persistent(self, value):
        self.node['persistent'] = value

    @property
    def collection(self):
        return self.branch['collection']

    @property
    def sync(self):
        return self.node['sync']

    @property
    def producible(self):
        return self.branch['producible']

    @property
    def style(self):
        return self.branch['style']

    @property
    def remote(self):
        if self.node['remote url'] is None:
            if 'remote' in self.match:
                try:
                    url = os.path.join(self.handler.node['remote base'], self.match['remote'].format(**dict(self.genealogy)))
                except KeyError as e:
                    # self.log.debug('failed to assemble remote URL for %s because parameter %s was missing.', self.uri, e)
                    pass
                else:
                    if self.parameters:
                        additional = {}
                        for k,v in self.parameters.items():
                            prototype = self.parameters.namespace.find(k)
                            if prototype and prototype.node[self.handler.name]:
                                # Rename the parameters to the resolver's syntax and utf8 encode them 
                                additional[prototype.node[self.handler.name]] = str(v).encode('utf8')

                        if additional:
                            # Break up the URL
                            parsed = list(urllib.parse.urlparse(url))

                            # URL escape the parameters and encode as a query string
                            suffix = urllib.parse.urlencode(additional)

                            if parsed[4]:
                                parsed[4] = '&'.join((parsed[4], suffix))
                            else:
                                parsed[4] = suffix

                            # Reassemble the URL
                            url = urllib.parse.urlunparse(parsed)
                    self.node['remote url'] = url

        return self.node['remote url']

    @remote.setter
    def remote(self, value):
        self.node['remote url'] = value

    @property
    def genealogy(self):
        return self.node['genealogy']

    @property
    def immutable(self):
        return self.node['immutable']

    @property
    def parameters(self):
        if self.node['query parameter'] is None:
            if 'query parameter' in self.match:
                o = Ontology(self.env, 'ns/service/genealogy')
                o.absorb(self.genealogy, self.match['query parameter'])
                if self.location:
                    o.absorb(self.location, self.match['query parameter'])
                self.node['query parameter'] = o
        return self.node['query parameter']

    @property
    def sources(self):
        return self.node['sources']

    @property
    def entries(self):
        return self.node['entries']

    @property
    def result(self):
        return self.node['result']

    @result.setter
    def result(self, value):
        self.node['result'] = value

    def add_entry(self, entry):
        if 'persistent' not in entry:
            entry['persistent'] = entry['branch']['persistent']
        self.entries.append(entry)

    def discover(self, genealogy):
        self.genealogy.absorb(genealogy, self.index, self.immutable)

    def prepare(self):
        self.remote = None
        self.node['query parameter'] = None

    def refresh(self):
        if (self.sync and
            self.producible and
            self.persistent and
            self.result and
            self.result['body'] is not None):

            offset = self.context['task execution']['started'] - self.result.modified
            horizon = offset.total_seconds()
            if 'horizon' in self.context['task execution']['task']:
                horizon -= self.context['task execution']['task']['horizon']
            if horizon > 0:
                self.log.debug('refreshing %s old document %s', offset, self.uri)
                self.result['body'] = None

    def override(self):
        if 'override' in self.branch:
            for k,v in self.branch['override'].items():
                self.genealogy[k] = v

    def activate(self):
        if self.result:
            self.result = Document(self.env, None, self.result)
 
class ResourceHandler(object):
    def __init__(self, resolver, node):
        self.log = logging.getLogger('Resolver')
        self.resolver = resolver
        self.node = node
        self.pattern = re.compile(self.node['match'])
        self.branch = {}

        for name, branch in self.node['branch'].items():
            branch['name'] = name
            if 'index' not in branch: branch['index'] = []

            if 'resolvable' in branch and any([ 'canonical' in r and r['canonical'] for r in branch['resolvable']]):
                branch['producible'] = True
            else:
                branch['producible'] = False

            # infer the collection to use for persistent branches
            branch['persistent'] = False
            branch['collection'] = None
            table = None
            if 'table' in branch:
                if branch['table'] in self.env.table:
                    table = self.env.table[branch['table']]
                    branch['collection'] = table['collection']
                    branch['persistent'] = True

                    # assign the default namespace for the table if one was not specified 
                    if 'namespace' in table and 'namespace' not in branch:
                        branch['namespace'] = table['namespace'] 
                else:
                    self.log.warning('reference to an unknown table %s in branch %s', branch['table'], branch['name'])            

            # Query style defaults to lookup
            if 'style' not in branch: branch['style'] = 'lookup'

            for match in branch['match']:
                # Compile match patterns
                match['pattern'] = re.compile(match['filter'])

                # Convert the query parameters declaration to a set
                # Those are used to either encode the remote URL or to search a table
                if 'query parameter' in match and match['query parameter']:
                    match['query parameter'] = set(match['query parameter'])
            self.branch[name] = branch

        for name, branch in self.node['branch'].items():
            if 'produce' in branch:
                for product in branch['produce']:
                    product['branch'] = self.branch[product['reference']]

    @property
    def env(self):
        return self.resolver.env

    @property
    def repository(self):
        return self.resolver.repository

    @property
    def name(self):
        return self.node['key']

    def handles(self, uri):
        return self.pattern.search(uri)

    def remove(self, uri):
        taken = False
        for branch in self.branch.values():
            for match in branch['match']:
                m = match['pattern'].search(uri)
                if m is not None:
                    taken = True
                    if branch['style'] == 'lookup':
                        if branch['persistent']:
                            collection = self.repository.database[branch['collection']]
                            record = collection.find_one({'head.alternate':uri})
                            if record:
                                document = Document(self.env, None, record)
                                collection.remove({'head.alternate':uri})
                                self.log.debug('dropped %s', uri)
                                self.remove_dependencies(document, branch)
                    break
            if taken: break

    def save(self, node):
        taken = False
        uri = node['head']['canonical']
        for branch in self.branch.values():
            for match in branch['match']:
                m = match['pattern'].search(uri)
                if m is not None:
                    taken = True
                    if branch['style'] == 'lookup':
                        query = Query(self, uri, None, None, branch, match, None)
                        query.add_entry({ 'branch': branch, 'record': node })
                        self.store(query)
                    break
            if taken: break

    def resolve(self, uri, location, context):
        for branch in self.branch.values():
            for match in branch['match']:
                m = match['pattern'].search(uri)
                if m is not None:
                    parsed = Ontology(self.env, 'ns/service/genealogy')
                    parsed.interpret(m.groupdict(), 'keyword')
                    query = Query(self, uri, location, context, branch, match, parsed)

                    self.locate(query)
                    query.refresh()
                    # if the document was not found we try to create it
                    if query.producible and (not query.result or query.result['body'] is None):
                        self.trigger(query)
                        self.collect(query)
                        self.fetch(query)
                        self.collect(query)
                        self.parse(query)
                        self.search(query)
                        self.store(query)
                        self.locate(query)
                    query.activate()
                    return query.result
        return None

    def search(self, query):
        if query.style == 'search':
            entry = {
                'branch':query.branch,
                'record': Document(self.env, query.branch['namespace'], {
                    'head': {
                        'genealogy': query.genealogy.project('ns/service/genealogy')
                    }
                })
            }
            entry['record'].genealogy.absorb(query.location, query.index)
            if 'produce' in query.branch:
                for product in query.branch['produce']:
                    if product['container'] not in entry['record'].body:
                        entry['record'].body[product['container']] = []

                    select = dict([ ('head.genealogy.{}'.format(str(k)), v) for k,v in query.parameters.items() if k in query.index ])
                    collection = self.repository.database[product['branch']['collection']]
                    cursor = collection.find(select)
                    for record in cursor:
                        document = Document(self.env, None, record)
                        if 'condition' not in product or satisfies(document.genealogy, product['condition']):
                            entry['record'].body[product['container']].append(document.genealogy)
            query.add_entry(entry)

    def locate(self, query):
        if query.style == 'lookup':
            if query.persistent:
                collection = self.repository.database[query.collection]
                if query.style == 'lookup':
                    existing = collection.find_one({'head.alternate':query.uri})
                    if existing:
                        query.result = Document(self.env, None, existing)
                        if query.index:
                            query.genealogy.absorb(query.result.genealogy, query.result.genealogy)
            elif query.entries:
                query.result = query.entries[0]['record']

        elif query.style == 'discover':
            if query.entries:
                if not query.result: 
                    query.result = Document(self.env, query.branch['namespace'], {
                        'head': {
                            'genealogy': query.genealogy.project('ns/service/genealogy')
                        },
                        'body': { 'references': [] }
                    })
                    query.result.genealogy.absorb(query.location, query.index)

                persistent = [ ]
                for entry in query.entries:
                    if entry['style'] == 'resolve':
                        # force language
                        entry['record'].genealogy['language']
                        for resolvable in entry['branch']['resolvable']:
                            try:
                                uri = resolvable['format'].format(**dict(entry['record'].genealogy))
                            except KeyError:
                                pass
                            else:
                                document = self.resolver.resolve(uri, None, query.context)
                                if document is not None:
                                    query.result.body['references'].append(document.head)
                                    break
                    elif entry['style'] == 'persist':
                        persistent.append(entry)
                query.entries.clear()
                query.entries.extend(persistent)
                query.result.body['result count'] = len(query.result.body['references'])

        elif query.style == 'search':
            if query.persistent:
                collection = self.repository.database[query.collection]
                existing = collection.find_one({'head.alternate':query.uri})
                if existing:
                    query.result = Document(self.env, None, existing)
                    if query.index:
                        query.genealogy.absorb(query.result.genealogy, query.result.genealogy)

    def collect(self, query):
        if 'collect' in query.branch:
            for pattern in query.branch['collect']:
                try:
                    uri = pattern.format(**dict(query.genealogy))
                    related = self.resolver.resolve(uri, query.location, query.context)
                except KeyError as e:
                    # self.log.debug('patten %s ignored because %s is missing', pattern, str(e))
                    pass
                else:
                    if related:
                        query.discover(related.genealogy)
                    else:
                        self.log.debug('document %s could not be resolved', uri)
        query.override()

    def fetch(self, query):
        query.prepare()
        if query.remote:
            request = Request(query.remote, None, { 'Accept': 'application/json' })
            self.log.debug('fetching %s', query.remote)

            try:
                response = urlopen(request)
            except BadStatusLine as e:
                self.log.warning('Bad http status error when requesting %s', query.remote)
            except HTTPError as e:
                self.log.warning('Server returned an error when requesting %s: %s', query.remote, e.code)
            except URLError as e:
                self.log.warning('Could not reach server when requesting %s: %s', query.remote, e.reason)
            else:
                try:
                    content = json.loads(response.read().decode('utf8'))
                except ValueError as e:
                    self.log.warning('Failed to decode JSON document %s', query.remote)
                    self.log.debug('Exception raised %s', unicode(e))
                else:
                    if content is not None and len(content) > 0:
                        query.sources.append(content)

    def parse(self, query):
        # Implemented by the individual handlers
        pass

    def store(self, query):
        if query.style in [ 'lookup' , 'discover' , 'search' ]:
            for entry in query.entries:
                if 'style' not in entry or entry['style'] == 'persist':
                    for word in ['api key', 'username']:
                        del entry['record'].genealogy[word]

                    entry['record'].modified = datetime.utcnow()
                    entry['record'].body.normalize()

                    self.assemble_resolvables(entry['record'], entry['branch'])

                    if entry['persistent']:
                        document = None
                        collection = self.repository.database[entry['branch']['collection']]
                        with self.resolver.lock:
                            # try to locate an existing record
                            for uri in entry['record'].alternate:
                                document = collection.find_one({'head.alternate':uri})
                                if document is not None:
                                    document = Document(self.env, None, document)
                                    break

                            if document is not None:
                                # this is an update, we already have an existing record
                                document.modified = entry['record'].modified

                                # new body replaces old
                                document['body'] = entry['record'].body

                                # replace original
                                if 'original' in document: del document['original']
                                if 'original' in entry['record']:
                                    document['original'] = entry['record']['original']

                                # new genealogy overlays the old
                                document.genealogy.overlay(entry['record'].genealogy)
                                self.assemble_resolvables(document, entry['branch'])

                            else:
                                # this is an insert, no previous existing record was found
                                document = entry['record']
                                document.created = document.modified

                                # issue new keys
                                if 'generated' in self.node:
                                    for pattern in self.node['generated']:
                                        self.assign_key(document.genealogy, pattern['element'], pattern['space'], entry['branch'])
                                        self.assemble_resolvables(document, entry['branch'])

                            # Make sure canonical and alternate are set
                            if document.canonical:
                                if document.alternate:
                                    self.log.debug('saving %s', str(document))

                                    try:
                                        collection.save(document)
                                    except DuplicateKeyError as error:
                                        self.log.error(str(error))
                                        raise InconsistencyError(str(error))
                                else:
                                    self.log.debug('refusing to save document with missing alternate address block\n{}'.format(self.env.to_json(document.head)))            
                            else:
                                self.log.debug('refusing to save record for {} with missing canonical address\n{}'.format(entry['branch']['name'], self.env.to_json(document.head)))

                            self.remove_dependencies(document, entry['branch'])

                    if query.style == 'discover':
                        entry['style'] = 'resolve'

        elif query.style == 'search':
            pass

    def trigger(self, query):
        if 'trigger' in query.match:
            immutable = dict([(k,v) for k,v in query.genealogy.items() if k in query.immutable])
            for pattern in query.match['trigger']:
                try:
                    related = self.resolver.resolve(pattern.format(**dict(immutable)), None, query.context)
                except KeyError as e:
                    # self.log.debug('failed to assemble related uri for pattern %s because parameter %s was missing', pattern, e)
                    pass

    def assign_key(self, genealogy, element, space, branch):
        if element not in genealogy:
            genealogy[element] = self.resolver.issue(space)
            self.log.debug('assigning %s to key %s',genealogy[element], element)

        if ('qualified key' in branch and
            element in branch['qualified key'] and 
            genealogy[branch['qualified key'][element]] != genealogy[element]):
            genealogy[branch['qualified key'][element]] = genealogy[element]
            self.log.debug('assigning %s to qualified key %s',genealogy[element], branch['qualified key'][element])

    def assemble_resolvables(self, document, branch):
        document.alternate.clear()
        document.canonical = None

        # Build all the resolvable URIs from the genealogy
        for resolvable in branch['resolvable']:
            try:
                link = resolvable['format'].format(**dict(document.genealogy))
                document.alternate.append(link)
                if 'canonical' in resolvable and resolvable['canonical']:
                    document.canonical = link
            except KeyError as e: pass

    def remove_dependencies(self, document, branch):
        if 'dependency' in branch:
            for dependency in branch['dependency']:
                try:
                    reference = dependency.format(**dict(document.genealogy))
                    self.log.debug('drop dependent %s', reference)
                    self.resolver.remove(reference)
                except KeyError as e: pass
