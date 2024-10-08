#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Copyright (C) 2008 General de Software de Canarias.
 
 Author: Carlos López Pérez <carlos.lopezperez@gmail.com>
 Heavily modified by András Korn, Miklós Molnár and Lőrinc Száray.
"""

import re
import ldap

from genshi.builder import tag
from trac.core import implements, Component
from trac.web.api import IRequestFilter, IRequestHandler
from trac.web.chrome import INavigationContributor, ITemplateProvider

class AccountLDAP(Component):
    """Get user attributes from LDAP and copy them into Trac database.
    """
    implements(IRequestFilter, INavigationContributor, ITemplateProvider,
               IRequestHandler)
    
    MODULE_NAME = 'accountldap'    
    
    def __init__(self):
        """Connects to ldap
        """
        self.basedn = self.config.get('ldap', 'basedn')
        self.userdn = self.config.get('ldap', 'user_rdn')
        self.attempts = 1
        if self.config.has_option('ldap', 'attempts'):
            self.attempts = self.config.getint('ldap', 'attempts')
        self.uidattr = 'uid'
        if self.config.has_option('ldap', 'uidattr'):
            self.uidattr = self.config.get('ldap', 'uidattr')
        self.userFilter = 'uid'
        if self.config.has_option('ldap', 'user_filter'):
            self.userFilter = self.config.get('ldap', 'user_filter')
        self.enabled = True
        for i in range(self.attempts):
            try:
                # Initialize connection
                self.ldap = \
                    ldap.ldapobject.ReconnectLDAPObject('%s%s' %
                                    (self.config.get('ldap', 'ldap_prefix'),
                                     self.config.get('ldap', 'host')),
                                     trace_level=2)
                self.ldap.protocol_version = ldap.VERSION3
                break
            except (ldap.LDAPError, e):
                self.log.error('LDAP connection problems. Check trac.ini'
                               ' ldap options. Attempt %i', (i + 1))
                self.enabled = False
        self.log.info('Connection LDAP basedn "%s" user_rdn "%s".'
                      ' Attempt %i' % (self.basedn, self.userdn, (i + 1)))

    #
    #------------------------------------------------- IRequestFilter interface
    #
    def pre_process_request(self, req, handler):
        return handler
    
    """If some session data is missing, connect to LDAP and fetch it.
    """
    def post_process_request(self, req, template, data, content_type):
        if (not req.authname) or (req.authname == 'anonymous'):
            self.log.debug('post_process_request(): returning early'
                           'as req.authname is null or anonymous.')
            return template, data, content_type
        updateName = False
        updateMail = False
        updateDN = False
        try:
            if req.session['email'] and req.session['name'] and req.session['dn']:
                self.log.debug('post_process_request(): returning early.'
                               'req.authname=%s, req.session[email]=%s',
                               (req.authname or ""), (req.session['email'] or ""))
                return template, data, content_type
            else:
                if not req.session['email']:
                    updateMail = True
                if not req.session['name']:
                    updateName = True
                if not req.session['dn']:
                    updateDN = True
        except KeyError:
            updateMail = True
            updateName = True
            updateDN = True
        
        if updateMail or updateName or updateDN:
            uid = req.authname.lower()
            self.log.debug('requesting user LDAP data for %s', uid)
            dn, name, email = self._getUserAttributes(uid)
            self.log.debug('post_process_request(): got name=%s, email=%s',
                           (name or ""), (email or ""))
        
            if updateName:
                req.session['name'] = name.decode('utf-8')
            if updateMail:
                req.session['email'] = email
            if updateDN:
                req.session['dn'] = dn
        return template, data, content_type

    #
    #----------------------------------------- INavigationContributor interface
    #
    def get_active_navigation_item(self, req):
        return self.MODULE_NAME
                
    def get_navigation_items(self, req):
        if not req.authname or not req.session.has_key('email'):
            return
        yield ('metanav', self.MODULE_NAME,
               tag.a(u'LDAP Password', href=req.href.accountldap()))
    #
    #------------------------------------------------ IRequestHandler interface
    #
    def match_request(self, req):
        return re.match(r'/%s(?:_trac)?(?:/.*)?$' %
                        self.MODULE_NAME, req.path_info)

    def process_request(self, req):
        data = {'accountldap_message': None}
        template = '%s.html' % self.MODULE_NAME
        if req.method != 'POST':
            return template, data, None
        p1 = req.args.get('password1')
        p2 = req.args.get('password2')
        old = req.args.get('oldpassword')
        if p1 != p2:
            data['accountldap_message'] = tag.center(u'The passwords do not match.', tag.b(u' Please enter the same password twice.'), style='color:chocolate')
            return template, data, None
        if old == p1:
            data['accountldap_message'] = tag.center(u'The old password is the same as the new password.', tag.b(u' Please supply a different password.'), style='color:chocolate')
            return template, data, None
        dn = req.session['dn']
        try:
            # Establish binding with the authenticated user's credentials
            self.ldap.simple_bind_s(dn, old)
            self.log.warn('Ldap change password dn. %s' % dn)
            # Update password
            self.ldap.passwd_s(dn, old, p1)
        except (ldap.LDAPError, e):
            data['accountldap_message'] = \
                tag.center(u'There was an error changing your password.',
                           tag.b(u' Please make sure the old password you'
                                 ' entered was correct.'),
                           style='color:chocolate')
            self.log.warn('Ldap change password. %s' % e)
            return template, data, None
        data['accountldap_message'] = \
            tag.center(tag.b(u'Your LDAP password has been updated successfully.'),
                       style='color:green')
        return template, data, None
    #
    #---------------------------------------------- ITemplateProvider interface
    #
    def get_htdocs_dirs(self): 
        return []
     
    def get_templates_dirs(self):
        from pkg_resources import resource_filename
        return [resource_filename(__name__, 'templates')]
    #
    #----------------------------------------------------------- helper methods
    #
    def _getUserAttributes(self, uid):
        """Returns the dn, cn and email address of the user as found in LDAP
        TODO: handle multivalued attributes
        TODO: make name of name attribute configurable (so that we can support e.g. displayName instead of cn)
        """
        filter = "(&(%s=%s)%s)" % \
            (self.uidattr.encode('ascii'), uid, self.userFilter)
        try:
            # get all attributes of the user
            # TODO we only need 'cn' and 'mail'
            self.log.debug('Trying LDAP search with basedn=%s, scope=%s, filter=%s, uri=%s' % (self.basedn, ldap.SCOPE_SUBTREE, filter, self.ldap._uri))
            id = self.ldap.search(self.basedn, ldap.SCOPE_SUBTREE, filter, None)
            # use the first match for the uid
            type, data = self.ldap.result(id, 0)
            dn = data[0][0]
            dict = data[0][1]
        except (ldap.LDAPError, e):
            self.log.error(str(e))
            self.log.error('Search LDAP problems. Check trac.ini ldap options')
            return ('', '', '')
        try:
            dn = data[0][0]
            dict = data[0][1]
        except Error:
            self.log.error('Logged in user not found in LDAP')
            return ('', '', '')
        try:
            cn = dict['cn'][0]
        except Error:
            self.log.error("Logged in user doesn't have a cn attribute")
            return (dn, '', '')
        try:
            mail = dict['mail'][0]
        except Error:
            self.log.error("Logged in user doesn't have a mail attribute")
            return (dn, cn, '')
        
        self.log.info('%s - %s - %s' % (dn, cn, mail))
        return (dn, cn, mail)
