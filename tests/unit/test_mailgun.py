#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mock
import unittest

from paste.util.multidict import MultiDict

import pyrax
from pyrax import exceptions as exc
from pyrax.mailgun import MAILGUN_API
from pyrax.mailgun import MailgunClient
from pyrax.mailgun import MailgunDomain
from pyrax.mailgun import MailgunManager
from pyrax.mailgun import requests

class TestMailgunClientBase(unittest.TestCase):
    """Class for testing MailgunClient functions."""

    @mock.patch.object(MailgunManager, 'fetch_apikey')
    def setUp(self, mock_fetch_key):
        """Re-use vars."""
        mock_fetch_key.return_value = 'test_auth'
        self.mock_fetch_key = mock_fetch_key
        self.client = MailgunClient()

    def test_name_assignment(self):
        self.assertEqual(self.client.name, "Mailgun")

    def test_management_url_assignment(self):
        self.assertEqual(self.client.management_url, MAILGUN_API)

    def test_auth_assignment(self):
        self.assertEqual(self.client.auth, ('api', 'test_auth'))

    def test_manager_assignment(self):
        assert isinstance(self.client._manager, MailgunManager)

    def test_manager_attributes(self):
        self.assertEqual(self.client._manager.resource_class, MailgunDomain)
        self.assertEqual(self.client._manager.response_key, 'domain')
        self.assertEqual(self.client._manager.plural_response_key, 'items')
        self.assertEqual(self.client._manager.uri_base, 'domains')

    @mock.patch.object(requests, 'get')
    def test_api_request_success(self, mock_requests):
        req = mock.Mock()
        req.json.return_value = {'testing': 'response'}
        req.status_code = 200
        mock_requests.return_value = req
        expected = (req.status_code, req.json())
        results = self.client._api_request('/blahblah', 'GET')
        self.assertEqual(expected, results)
        mock_requests.assert_called_with('https://api.mailgun.net/v2/blahblah',
            headers={'Accept': 'application/json'}, auth=('api', 'test_auth'))

    @mock.patch.object(requests, 'get')
    def test_api_request_exception(self, mock_requests):
        mock_requests.side_effect = requests.exceptions.RequestException('test')
        self.assertRaisesRegexp(exc.ClientException, 'Unknown error occurred '
            'in api request', self.client._api_request, '/blahblah', 'GET')

    @mock.patch.object(MailgunClient, 'method_post')
    def test_create_mailing_list(self, mock_post):
        return_json = {
            'list': {
                'access_level': 'readonly',
                'address': 'test@test.com',
                'created_at': 'Fri, 27 Sep 2013 20:54:39 GMT',
                'description': 'testing',
                'members_count': 0,
                'name': ''
            },
            'message': 'Mailing list has been created'
        }
        mock_post.return_value = (200, return_json)
        results = self.client.create_mailing_list('test@test.com', 'testing')
        self.assertEqual(results, (200, return_json))
        mock_post.assert_called_with('/lists', data={'description': 'testing',
            'address': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_add_list_member(self, mock_post):
        return_json = {
            "member": {
                "subscribed": True,
                "name": "",
                "vars": {},
                "address": "joe@test.com"
            },
            "message": "Mailing list member has been created"
        }
        mock_post.return_value = (200, return_json)
        results = self.client.add_list_member('test@test.com', 'joe@test.com')
        self.assertEqual(results, (200, return_json))
        mock_post.assert_called_with('/lists/test@test.com/members',
            data={'subscribed': True, 'address': 'joe@test.com'})

    @mock.patch.object(MailgunClient, 'method_put')
    def test_update_list_member(self, mock_put):
        return_json = {
            "member": {
                "subscribed": False,
                "name": "",
                "vars": {},
                "address": "joe@test.com"
            },
            "message": "Mailing list member has been updated"
        }
        mock_put.return_value = (200, return_json)
        results = self.client.update_list_member('test@test.com',
            'joe@test.com', subscribed=False)
        self.assertEqual(results, (200, return_json))
        mock_put.assert_called_with('/lists/test@test.com/members/joe@test.com',
            data={'subscribed': False})

    @mock.patch.object(MailgunClient, 'method_get')
    def test_list_members(self, mock_get):
        return_json = {
            "items": [
                {
                    "subscribed": True,
                    "name": "",
                    "vars": {},
                    "address": "joe@test.com"
                }
            ],
            "total_count": 1
        }
        mock_get.return_value = (200, return_json)
        results = self.client.list_members('test@test.com')
        self.assertEqual(results, (200, return_json))
        mock_get.assert_called_with('/lists/test@test.com/members')

    @mock.patch.object(MailgunClient, 'method_get')
    def test_get_list_stats(self, mock_get):
        return_json = {
            "unique": {
                "clicked": {
                    "recipient": 0,
                    "link": 0
                },
                "opened": {
                    "recipient": 0
                }
            },
            "total": {
                "complained": 0,
                "delivered": 0,
                "clicked": 0,
                "opened": 0,
                "unsubscribed": 0,
                "bounced": 0,
                "dropped": 0
            }
        }
        mock_get.return_value = (200, return_json)
        results = self.client.get_list_stats('test@test.com')
        self.assertEqual(results, (200, return_json))
        mock_get.assert_called_with('/lists/test@test.com/stats')

    @mock.patch.object(MailgunClient, 'method_delete')
    def test_delete_list_member(self, mock_delete):
        return_json = {
            "member": {
                "address": "joe@test.com"
            },
            "message": "Mailing list member has been deleted"
        }
        mock_delete.return_value = (200, return_json)
        results = self.client.delete_list_member('test@test.com',
            'joe@test.com')
        self.assertEqual(results, (200, return_json))
        mock_delete.assert_called_with('/lists/test@test.com/members/joe@test.com')

    @mock.patch.object(MailgunClient, 'method_delete')
    def test_delete_mailing_list(self, mock_delete):
        return_json = {
            "message": "Mailing list has been deleted",
            "address": "list2@natesjerky.com"
        }
        mock_delete.return_value = (200, return_json)
        results = self.client.delete_mailing_list('test@test.com')
        self.assertEqual(results, (200, return_json))
        mock_delete.assert_called_with('/lists/test@test.com')

    @mock.patch.object(MailgunClient, 'method_post')
    def test_create_domain_success(self, mock_post):
        """Verifies method calls and results when creating domain."""
        return_json = {
            "domain": {
                "created_at": "Wed, 27 Oct 2013 18:38:22 GMT",
                "smtp_login": "postmaster@test.com",
                "name": "test.com",
                "smtp_password": "supasecret"
            },
            "message": "Domain has been created"
        }
        mock_post.return_value = (200, return_json)
        domain = self.client.create('test.com', 'supasecret')
        self.assertEqual('test.com', domain.name)
        self.assertEqual('supasecret', domain.smtp_password)
        mock_post.assert_called_with('/domains', data={'name': 'test.com',
            'smtp_password': 'supasecret'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_create_domain_400(self, mock_post):
        mock_post.return_value = (400, {'message': 'testing'})
        self.assertRaisesRegexp(exc.DomainRecordNotUnique, "testing",
            self.client.create, 'test.com', 'blah')

    @mock.patch.object(MailgunClient, 'method_post')
    def test_create_domain_500(self, mock_post):
        mock_post.return_value = (500, {'message': 'Unknown Error'})
        self.assertRaisesRegexp(exc.DomainCreationFailed, "Unknown Error",
                self.client.create, 'test.com', 'blah')

    @mock.patch.object(MailgunClient, 'method_get')
    def test_get_domain(self, mock_get):
        return_json = {
            "domain": {
                "created_at": "Wed, 27 Oct 2013 18:38:22 GMT",
                "smtp_login": "postmaster@test.com",
                "name": "test.com",
                "smtp_password": "supasecret"
            },
            "receiving_dns_records": [
                {"record_type" : "MX", "priority": 10, "value": "mxa.mailgun.org"},
                {"record_type" : "MX", "priority": 10, "value": "mxb.mailgun.org"}
            ],
            "sending_dns_records": [
                {"record_type" : "TXT", "name": "samples.mailgun.org", "value": 1},
                {"record_type" : "CNAME", "name": "email.samples.mailgun.org", "value": 1}
            ]
        }
        mock_get.return_value = (200, return_json)
        domain = self.client.get('test.com')
        self.assertEqual(domain.receiving_dns_records, return_json['receiving_dns_records'])
        self.assertEqual(domain.sending_dns_records, return_json['sending_dns_records'])

    @mock.patch.object(MailgunClient, 'method_delete')
    def test_delete_domain(self, mock_delete):
        mock_delete.return_value = (500, {'message': 'Failed Delete'})
        self.assertRaisesRegexp(exc.DomainDeletionFailed, 'Failed Delete',
            self.client.delete, 'test.com')


class TestDomainResource(unittest.TestCase):
    """Class for testing domain resources."""

    @mock.patch.object(MailgunClient, 'method_post')
    def _create_test_domain(self, client, dom_name, password, mock_post):
        return_json = {
            "domain": {
                "created_at": "Wed, 27 Oct 2013 18:38:22 GMT",
                "smtp_login": "postmaster@test.com",
                "name": "test.com",
                "smtp_password": "supasecret"
            },
            "message": "Domain has been created"
        }
        mock_post.return_value = (200, return_json)
        return client.create(dom_name, password)
        
    @mock.patch.object(MailgunManager, 'fetch_apikey')
    def setUp(self, mock_fetch_key):
        """Re-use vars."""
        mock_fetch_key.return_value = 'test_auth'
        self.mock_fetch_key = mock_fetch_key
        self.client = MailgunClient()
        self.domain = self._create_test_domain(self.client, 'test.com',
            'supasecret')

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_files(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                files=['testfile'])
        mock_post.assert_called_with('/test.com/messages',
                files=MultiDict([('attachment', 'testfile')]),
                data={'to': ['testing@test.com'], 'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_inline_images(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                inline_images=['testimage'])
        mock_post.assert_called_with('/test.com/messages',
                files=MultiDict([('inline', 'testimage')]),
                data={'to': ['testing@test.com'], 'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_mime(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                mime_file='test_mime_file')
        mock_post.assert_called_with('/test.com/messages',
                files={'message': 'test_mime_file'}, 
                data={'to': ['testing@test.com'], 'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_no_tracking(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                tracking=False)
        mock_post.assert_called_with('/test.com/messages', files=[],
                data={'to': ['testing@test.com'], 'o:tracking': False,
                'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_scheduled(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                delivery_time="Thu, 31 Oct 2013 18:38:22 GMT")
        mock_post.assert_called_with('/test.com/messages', files=[],
                data={'to': ['testing@test.com'],
                'o:deliverytime': 'Thu, 31 Oct 2013 18:38:22 GMT',
                'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_tags(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                tags=[{'interests': 'cars'}])
        mock_post.assert_called_with('/test.com/messages', files=[],
                data={'interests': 'cars', 'to': ['testing@test.com'],
                'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_post')
    def test_send_message_vars(self, mock_post):
        self.domain.send_message('test@test.com', ['testing@test.com'],
                recipient_vars=('{"bob@example.com": {"first":"Bob", "id":1}'))
        mock_post.assert_called_with('/test.com/messages', files=[],
                data={'to': ['testing@test.com'],
                'recipient-variables': '{"bob@example.com": {"first":"Bob", "id":1}',
                'from': 'test@test.com'})

    @mock.patch.object(MailgunClient, 'method_get')
    def test_get_logs(self, mock_get):
        self.domain.get_logs('Wed, 27 Oct 2013 18:38:22 GMT', sender='test@test.com',
                receiver='testing@test.com')
        mock_get.assert_called_with('/test.com/events',
                params={'begin': 'Wed, 27 Oct 2013 18:38:22 GMT',
                'pretty': 'yes', 'ascending': 'yes', 'limit': 100,
                'f:recipient': 'test@test.com', 't:recipient': 'testing@test.com'})

    @mock.patch.object(MailgunClient, 'method_get')
    def test_get_stats(self, mock_get):
        self.domain.get_stats(['opened'])
        mock_get.assert_called_with('/test.com/stats',
                params={'skip': 0, 'limit': 100, 'event': ['opened']})

    @mock.patch.object(MailgunClient, 'method_get')
    def test_list_mailboxes(self, mock_get):
        self.domain.list_mailboxes()
        mock_get.assert_called_with('/test.com/mailboxes')

    @mock.patch.object(MailgunClient, 'method_post')
    def test_create_mailbox(self, mock_post):
        self.domain.create_mailbox('tested@test.com', 'supasecret')
        mock_post.assert_called_with('/test.com/mailboxes',
                data={'password': 'supasecret', 'mailbox': 'tested@test.com'})

    @mock.patch.object(MailgunClient, 'method_put')
    def test_change_mailbox_password(self, mock_put):
        self.domain.change_mailbox_password('tested@test.com', 'newsecret')
        mock_put.assert_called_with('/test.com/mailboxes/tested@test.com',
                data={'password': 'newsecret'})

    @mock.patch.object(MailgunClient, 'method_delete')
    def test_delete_mailbox(self, mock_delete):
        self.domain.delete_mailbox('tested@test.com')
        mock_delete.assert_called_with('/test.com/mailboxes/tested@test.com')


class TestMailgunManager(unittest.TestCase):
    """Class for testing not already tested manager methods."""

    @mock.patch.object(requests, 'get')
    @mock.patch.object(pyrax, 'identity')
    def test_fetch_apikey(self, mock_identity, mock_get):
        return_value = {'api_key': 'alskjdghalksdjfh'}
        request_obj = mock.Mock()
        request_obj.json.return_value = return_value
        mock_get.return_value = request_obj
        client = MailgunClient()
        mock_get.assert_called_with('https://mailgun.com/rackspace/accounts',
                headers={'Accept': 'application/json'},
                params={'auth_token': mock_identity.token,
                'account_id': mock_identity.tenant_id})
        self.assertEqual(client.auth, ('api', 'alskjdghalksdjfh'))

    @mock.patch.object(requests, 'get')
    @mock.patch.object(pyrax, 'identity')
    def test_fetch_apikey_unauthorized(self, mock_identity, mock_get):
        return_value = {"message": "Unauthorized"}
        request_obj = mock.Mock()
        request_obj.json.return_value = return_value
        request_obj.text = return_value['message']
        request_obj.status_code = 401
        mock_get.return_value = request_obj
        self.assertRaisesRegexp(exc.AuthorizationFailure, "Unauthorized",
                MailgunClient)

    @mock.patch.object(requests, 'get')
    @mock.patch.object(pyrax, 'identity')
    def test_fetch_apikey_request_exception(self, mock_identity, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException()
        self.assertRaisesRegexp(exc.AuthenticationFailed,
                "Unable to connect to mailgun accounts api", MailgunClient)

