#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2013 Rackspace

# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import requests
from paste.util.multidict import MultiDict

import pyrax
from pyrax.client import BaseClient
from pyrax import exceptions
from pyrax.manager import BaseManager
from pyrax.resource import BaseResource
from pyrax import utils

MAILGUN_API = "https://api.mailgun.net/v2"
MAILGUN_ACCOUNTS_API = "https://mailgun.com"
HEADERS = {"Accept": "application/json"}


class MailgunDomain(BaseResource):
    """
    This class represents a Mailgun domain.
    """
    def __init__(self, *args, **kwargs):
        super(MailgunDomain, self).__init__(*args, **kwargs)
        # Mailgun uses the domain as the unique identifier.
        self.id = self.name

    def send_message(self, sender, recipients, **kwargs):
        """Send an email message.
            :param dom_name: string name
            :param sender: string email address
            :param recipients: string or list of string email addresses
            :param subject: string
            :param text: string for plain text msgs
            :param cc: string or list of string addresses
            :param bcc: same as cc
            :param html: string
            :param files: list of python file objects
            :param mime_file: python file object
            :param tracking: bool defaults to True
            :param delivery_time: date time string
            :param tags: list of dicts for custom attrs ie [{'age': 32}]
            :param inline_images: list of python file objects. Access via cid
            :param recipient_vars: tuple for custom email variables ex.
                   ('{"bob@example.com": {"first":"Bob", "id":1}) can be accessed
                   via %recipient.first% anywhere in the subject or text body.
        """
        return self.manager.send_message(self.name, sender, recipients, **kwargs)


    def get_logs(self, start_time, limit=100, ascending="yes", pretty="yes",
            sender=None, receiver=None):
        """Return event logs for domain.
            :params start_time: date time string
            :params limit: for pagination int
            :params ascending: ordering string
            :params pretty: pretty print string
            :params sender: email string
            :params receiver: email string
        """
        return self.manager.get_logs(self.name, start_time, limit, ascending,
                pretty, sender, receiver)


    def get_stats(self, events, skip=0, limit=100):
        """
        Return event stats for domain.
            :params events: list of events ex ["sent", "opened"]
            :params skip: offset int
            :params limit: int
        """
        return self.manager.get_stats(self.name, events, skip, limit)


    def list_mailboxes(self):
        """Returns list of mailboxes on current domain."""
        return self.manager.list_mailboxes(self.name)


    def create_mailbox(self, mailbox_address, password):
        """Creates mailbox on current domain."""
        return self.manager.create_mailbox(self.name, mailbox_address, password)


    def change_mailbox_password(self, mailbox_name, password):
        """Changes mailbox account password."""
        return self.manager.change_mailbox_password(self.name, mailbox_name,
                password)


    def delete_mailbox(self, mailbox_name):
        """Deletes specified mailbox from current domain."""
        return self.manager.delete_mailbox(self.name, mailbox_name)


###
# Not yet implemented in pyrax
###
'''
    def create_campaign(self, name, campaign_id):
        """Creates an email campaign."""
        return self.manager.create_campaign(self.name, campaign_id)


    def send_campaign_message(self, sender, recipients, subject, text,
            campaign_id):
        """Send a message to an existing campaign.
            :params sender: email string
            :params recipients: list of emails
            :params subject: string
            :params text: string
            :params campaign_id: sting
        """
        return self.manager.send_campaign_message(self.name, sender, recipients,
                subject, text, campaign_id)


    def get_campaign_stats(self, campaign_id, limit=None, group_by=None):
        """Get statistics on campaign messages."""
        return self.manager.get_campaign_stats(self.name, campaign_id,
                limit=limit, group_by=group_by)


    def list_webhooks(self):
        """Lists current webhooks on current domain."""
        return self.manager.list_webhooks(self.name)


    def get_webhook(self, webhook):
        """Returns data on specified webhook for current domain."""
        return self.manager.get_webhook(self.name, webhook)


    def create_webhook(self, webhook, url):
        """Creates specified webhook on current domain."""
        return self.manager.create_webhook(self.name, webhook, url)


    def update_webhook(self, webhook, url):
        """Updates the specified webhook with the provided url on current dom."""
        return self.manager.update_webhook(self.name, webhook, url)


    def delete_webhook(self, webhook):
        """Deletes specified webhook from current domain."""
        return self.manager.delete_webhook(self.name, webhook)
'''


class MailgunManager(BaseManager):
    """
    Handles interactions with the Mailgun API.
    """
    def fetch_apikey(self):
        """Returns Mailguin api key from valid token/tenant."""
        url = "%s/rackspace/accounts" % MAILGUN_ACCOUNTS_API
        ident = pyrax.identity
        data = {"account_id": ident.tenant_id, "auth_token": ident.token}
        try:
            req = requests.get(url, params=data, headers=HEADERS)
            response = req.json()["api_key"]
        except KeyError:
            raise exceptions.AuthorizationFailure("(%s) %s" % (req.status_code,
                    req.text))
        except requests.exceptions.RequestException as exc:
            raise exceptions.AuthenticationFailed("Unable to connect to "
                    "mailgun accounts api: %s" % exc)
        return response


    def create(self, dom_name, smtp_pass):
        """Creates Mailgun domain with supplied password."""
        data = {"name": dom_name, "smtp_password": smtp_pass}
        return self._create("/domains", data=data)


    def _create(self, uri, data):
        resp, resp_body = self.api.method_post(uri, data=data)
        if resp == 400:
            raise exceptions.DomainRecordNotUnique("(%s) %s" % (resp,
                    resp_body['message']))
        elif resp not in range(200,300):
            raise exceptions.DomainCreationFailed("(%s) %s" % (resp,
                    resp_body['message']))
        return self.resource_class(self, resp_body.get(self.response_key))


    def get(self, dom_name):
        """Returns details of specified domain."""
        return self._get("/domains/" + dom_name)


    def _get(self, uri):
        resp, resp_body = self.api.method_get(uri)
        # Flatten the response dict
        key = resp_body.get(self.response_key, {})
        key["receiving_dns_records"] = resp_body["receiving_dns_records"]
        key["sending_dns_records"] = resp_body["sending_dns_records"]
        return self.resource_class(self, key)


    def _delete(self, uri):
        """Overloads delete to catch invalid response codes."""
        resp, resp_body = self.api.method_delete(uri)
        if resp not in range(200, 300):
            raise exceptions.DomainDeletionFailed("(%s) %s" % (resp,
                    resp_body['message']))


    def send_message(self, dom_name, sender, recipients, **kwargs):
        """Send an email message.
            :param dom_name: string name
            :param sender: string email address
            :param recipients: string or list of string email addresses
            :param subject: string
            :param text: string for plain text msgs
            :param cc: string or list of string addresses
            :param bcc: same as cc
            :param html: string
            :param files: list of python file objects
            :param mime_file: python file object
            :param tracking: bool defaults to True via api
            :param delivery_time: date time string
            :param tags: list of dicts for custom attrs ie [{'age': 32}]
            :param inline_images: list of python file objects. Access via cid
            :param recipient_vars: tuple for custom email variables ex.
                   ('{"bob@example.com": {"first":"Bob", "id":1}') can be accessed
                   via %recipient.first% anywhere in the subject or text body.
        """
        files = []
        uri = "/%s/messages" % dom_name
        data = {"from": sender, "to": recipients}
        if kwargs.get('files'):
            attachments = kwargs.pop('files')
            files = MultiDict()
            for attachment in attachments:
                files.add("attachment", attachment)
        if kwargs.get('inline_images'):
            images = kwargs.pop('inline_images')
            if not files:
                files = MultiDict()
            for image in images:
                files.add('inline', image)
        if kwargs.get('mime_file'):
            mime_file = kwargs.pop('mime_file')
            files = {"message": mime_file}
        if kwargs.get('tracking') is False:
            kwargs['o:tracking'] = kwargs.pop('tracking')
        if kwargs.get('delivery_time'):
            kwargs["o:deliverytime"] = utils.rfc2822_format(kwargs.pop('delivery_time'))
        if kwargs.get('tags'):
            for tag in kwargs.pop('tags'):
                data.update(tag)
        if kwargs.get('recipient_vars'):
            kwargs['recipient-variables'] = kwargs.pop('recipient_vars')
        data.update(kwargs)
        return self.api.method_post(uri, data=data, files=files)


    def get_logs(self, dom_name, start_time, limit=100, ascending="yes",
            pretty="yes", sender=None, receiver=None):
        uri = "/%s/events" % dom_name
        params = {"begin": start_time,
                "ascending": ascending,
                "limit": limit,
                "pretty": pretty}
        if sender:
            params["f:recipient"] = sender
        if receiver:
            params["t:recipient"] = receiver
        return self.api.method_get(uri, params=params)


    def get_stats(self, dom_name, events, skip, limit):
        uri = "/%s/stats" % dom_name
        params = {"event": events,
                "skip": skip,
                "limit": limit,
                }
        return self.api.method_get(uri, params=params)


    def list_mailboxes(self, dom_name):
        uri = "/%s/mailboxes" % dom_name
        return self.api.method_get(uri)


    def create_mailbox(self, dom_name, mailbox_address, password):
        uri = "/%s/mailboxes" % dom_name
        data = {"mailbox": mailbox_address,
                "password": password}
        return self.api.method_post(uri, data=data)


    def change_mailbox_password(self, dom_name, mailbox_name, password):
        uri = "/%s/mailboxes/%s" % (dom_name, mailbox_name)
        data = {"password": password}
        return self.api.method_put(uri, data=data)


    def delete_mailbox(self, dom_name, mailbox_name):
        uri = "/%s/mailboxes/%s" % (dom_name, mailbox_name)
        return self.api.method_delete(uri)


    def create_mailing_list(self, address, description):
        uri= "/lists"
        data = {"address": address,
                "description": description,
                }
        return self.api.method_post(uri, data=data)


    def add_list_member(self, list_name, address, **kwargs):
        uri = "/lists/%s/members" % list_name
        data = {"subscribed": True, "address": address}
        data.update(kwargs)
        return self.api.method_post(uri, data=data)


    def update_list_member(self, list_name, address, **kwargs):
        uri = "/lists/%s/members/%s" % (list_name, address)
        return self.api.method_put(uri, data=kwargs)


    def list_members(self, list_name):
        uri = "/lists/%s/members" % list_name
        return self.api.method_get(uri)


    def delete_list_member(self, list_name, member_name):
        uri = "/lists/%s/members/%s" % (list_name, member_name)
        return self.api.method_delete(uri)


    def delete_mailing_list(self, list_name):
        uri = "/lists/%s" % list_name
        return self.api.method_delete(uri)


    def get_list_stats(self, list_name):
        uri = "/lists/%s/stats" % list_name
        return self.api.method_get(uri)


###
# Not Yet Implemeted in pyrax
###
"""
    def create_campaign(self, dom_name, name, campaign_id):
        uri = "/%s/campaigns" % dom_name
        data = {"name": name,
                "id": campaign_id,
                }
        return self.api.method_post(uri, data=data)


    def send_campaign_message(self, dom_name, sender, recipients, subject,
            text, campaign_id):
        uri = "/%s/messages" % dom_name
        data = {"from": sender,
                "to": recipients,
                "subject": subject,
                "text": text,
                "o:campaign": campaign_id,
                }
        return self.api.method_post(uri, data=data)


    def get_campaign_stats(self, dom_name, campaign_id, limit=20,
            group_by="daily_hour"):
        uri = "/%s/campaigns/%s/stats?groupby=%s&limit=%s" % (dom_name,
                campaign_id, group_by, limit)
        return self.api.method_get(uri)


    def list_webhooks(self, dom_name):
        uri = "/domains/%s/webhooks" % dom_name
        return self.api.method_get(uri)


    def get_webhook(self, dom_name, webhook):
        uri = "/domains/%s/webhooks/%s"
        return self.api.method_get(uri)


    def create_webhook(self, dom_name, webhook, url):
        uri = "/domains/%s/webhooks"
        data = {"id": webhook,
                "url": url,
                }
        return self.api.method_post(uri, data=data)


    def update_webhook(self, dom_name, webhook, url):
        uri = "/domains/%s/webhooks/%s" % webhook
        data = {"url": url}
        return self.api.method_put(uri, data=data)


    def delete_webhook(self, dom_name, webhook):
        uri = "/domains/%s/webhooks/%s" % webhook
        return self.api.method_delete(uri)


    def create_mailing_list(self, address, description):
        uri= "/lists"
        data = {"address": address,
                "description": description,
                }
        return self.api.method_post(uri, data=data)


    def add_list_member(self, list_name, name, address, description, extra):
        uri = "lists/%s/members" % list_name
        data = {"subscribed": True,
                "address": address,
                "name": name,
                "description": description,
                "vars": extra,
                }
        return self.api.method_post(uri, data=data)


    def update_list_member(self, list_name, name, address, description, extra,
            subscribed=True):
        uri = "lists/%s/members" % list_name
        data = {"subscribed": subscribed,
                "address": address,
                "name": name,
                "description": description,
                "vars": extra,
                }
        return self.api.method_put(uri, data=data)

=======
"""


class MailgunClient(BaseClient):
    """
    This is the base client for creating and managing Mailgun.
    """
    def __init__(self, *args, **kwargs):
        super(MailgunClient, self).__init__(*args, **kwargs)
        self.name = "Mailgun"
        self.management_url = MAILGUN_API
        self.auth = ("api", self._manager.fetch_apikey())


    def _configure_manager(self):
        """
        Creates the Manager instance to handle mailgun.
        """
        self._manager = MailgunManager(self, resource_class=MailgunDomain,
                response_key="domain", plural_response_key="items",
                uri_base="domains")


    def _api_request(self, uri, method, **kwargs):
        """
        Uses requests to perform api request.
        """
        try:
            print self.management_url + uri
            req = getattr(requests, method.lower())(self.management_url + uri,
                headers=HEADERS, auth=self.auth, **kwargs)
            print req.text
            print req.status_code
            response = req.json()
            code = req.status_code
        except requests.exceptions.RequestException as exc:
            raise exceptions.ClientException(code='500', message='Unknown '
                    'error occurred in api request.', details=str(exc))
        return code, response


    def create_mailing_list(self, address, description):
        return self._manager.create_mailing_list(address, description)


    def add_list_member(self, list_name, address, **kwargs):
        return self._manager.add_list_member(list_name, address, **kwargs)


    def update_list_member(self, list_name, address, **kwargs):
        return self._manager.update_list_member(list_name, address, **kwargs)


    def list_members(self, list_name):
        return self._manager.list_members(list_name)


    def delete_list_member(self, list_name, member_name):
        return self._manager.delete_list_member(list_name, member_name)\


    def delete_mailing_list(self, list_name):
        return self._manager.delete_mailing_list(list_name)


    def get_list_stats(self, list_name):
        return self._manager.get_list_stats(list_name)
