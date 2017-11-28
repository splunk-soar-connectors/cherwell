# --
# File: cherwell_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
from cherwell_consts import *
import requests
from requests.structures import CaseInsensitiveDict
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CherwellConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CherwellConnector, self).__init__()
        self._state = None
        self._base_url = None
        self._username = None
        self._password = None
        self._client_id = None
        self._token = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, form_data=None, method="get"):
        resp_json = None
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                json=data,
                data=form_data,
                headers=headers,
                params=params
            )
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _make_rest_call_file(self, endpoint, action_result, headers=None, params=None, data=None, form_data=None, method="get"):
        # This is used for making a rest call which will return a file (whihc would just be a string of bytes)
        # No need for as much validation of the output here
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)))

        url = self._base_url + endpoint
        try:
            r = request_func(
                url,
                json=data,
                data=form_data,
                headers=headers,
                params=params
            )
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))))

        if r.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, r.content)
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Error returned from server: {}".format(r.text)))

    def _get_oauth_token(self, action_result):
        data = {
            'grant_type': 'password',
            'client_id': self._client_id,
            'username': self._username,
            'password': self._password
        }
        ret_val, response = self._make_rest_call(CHERWELL_API_TOKEN, action_result, form_data=data, method='post')
        if phantom.is_fail(ret_val):
            return ret_val
        self._token = response
        return ret_val

    def _make_rest_call_helper(self, endpoint, action_result, headers=None, get_file=False, **kwargs):
        # Handle authentication before _make_rest_call
        if not self._token:
            ret_val = self._get_oauth_token(action_result)
            if phantom.is_fail(ret_val):
                return ret_val
        if headers is None:
            headers = {}
        headers.update({
            'Authorization': 'Bearer {}'.format(self._token['access_token'])
        })
        if get_file:
            return self._make_rest_call_file(endpoint, action_result, headers=headers, **kwargs)

        return self._make_rest_call(endpoint, action_result, headers=headers, **kwargs)

    def _get_customer_recid(self, action_result, full_name):
        ret_val, busobid_cid = self._get_busobid(action_result, 'CustomerInternal')
        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        endpoint = CHERWELL_API_GET_OBJECT_SCHEMA.format(busobid=busobid_cid)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)
        if phantom.is_fail(response):
            return RetVal(ret_val)

        field_id = self._get_field_id(response['fieldDefinitions'], 'Full name')

        search_request = {
            'busObId': busobid_cid,
            'filters': [
                {
                    'fieldId': field_id,
                    'operator': 'eq',
                    'value': full_name
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(
            CHERWELL_API_GET_SEARCH_RESULT, action_result,
            data=search_request, method='post'
        )
        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        try:
            recid = response['businessObjects'][0]['busObRecId']
        except IndexError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to find user by that name")
            )

        return RetVal(phantom.APP_SUCCESS, recid)

    def _get_busobid(self, action_result, bus_obj):
        endpoint = CHERWELL_API_OBJ_SUMMARY.format(busobname=bus_obj)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        try:
            busobid = response[0]['busObId']
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to retrieve Business Object ID"))

        return RetVal(phantom.APP_SUCCESS, busobid)

    def _mogrify_fields(self, action_result, business_object):
        # Transform a list of json objects into a dictionary
        fields = business_object['fields']
        fields_dict = {x.pop('name'): x for x in fields}
        business_object['fields'] = fields_dict

    def _get_field_id(self, fields, display_name):
        field_id = None
        for field in fields:
            if field['displayName'] == display_name:
                field_id = field['fieldId']
        return field_id

    def _set_field_values(self, fields, field_value_map):
        for f in fields:
            name = f['name']
            new_value = field_value_map.get(name)
            if new_value:
                f['value'] = new_value
                f['dirty'] = True

    def _download_save_attachments(self, action_result, attachments):
        for attachment in attachments:
            if attachment['attachmentType'] != 0:
                continue  # It's not a file
            endpoint = CHERWELL_GET_ATTACHMENT.format(
                attachmentid=attachment['attachmentId'],
                busobid=attachment['busObId'],
                busobrecid=attachment['busObRecId']
            )
            ret_val, response = self._make_rest_call_helper(
                endpoint, action_result, get_file=True
            )
            if phantom.is_fail(ret_val):
                return ret_val
            file_path = '/opt/phantom/vault/tmp/{}'.format(attachment['attachmentFileName'])
            with open(file_path, 'wb+') as fp:
                fp.write(response)
                fp.close()
                Vault.add_attachment(file_path, self.get_container_id())
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Validating Authorization Credentials...")
        ret_val = self._get_oauth_token(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        user_record_id = param['id']
        endpoint = CHERWELL_GET_USER_RECORD_ID.format(recid=user_record_id)

        ret_val, response = self._make_rest_call_helper(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return ret_val
        self._mogrify_fields(action_result, response)
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved user information")

    def _handle_list_users(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
            'loginidfilter': 'both'
        }

        ret_val, response = self._make_rest_call_helper(CHERWELL_LIST_USERS, action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        # Format each user in the list
        for user in response['users']:
            self._mogrify_fields(action_result, user)
            action_result.add_data(user)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the list of users")

    def _handle_get_attachments(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        public_id = param['id']
        save_attachmets = param.get('save_to_vault', False)
        bus_obj = param.get('object', 'Incident')
        ret_val, busobid = self._get_busobid(action_result, bus_obj)
        if phantom.is_fail(ret_val):
            return ret_val

        attachment_search_body = {
            "busObId": busobid,
            "busObPublicId": public_id,
            "types": [
                "None",
                "File",
                "FileManagerFile",
                "BusOb",
                "History",
                "Other"
            ],
            "attachmentTypes": [
                "Imported",
                "Linked",
                "URL"
            ]
        }

        ret_val, response = self._make_rest_call_helper(
            CHERWELL_GET_ATTACHMENTS, action_result, data=attachment_search_body, method="post"
        )
        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        if save_attachmets:
            ret_val = self._download_save_attachments(action_result, response['attachments'])
            if phantom.is_fail(ret_val):
                return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Retrieved Attachments")

    def _handle_update_ticket(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        public_id = param['id']
        vault_id = param.get('file')
        other = param.get('other')
        if other is None and vault_id is None:
            return action_result.set_status(phantom.APP_ERROR, "There is nothing to be updated")

        if other:
            try:
                other_dict = json.loads(other)
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "Error loading JSON Object", e
                )
            field_value_map = CaseInsensitiveDict()
            field_value_map.update(other_dict)
        else:
            field_value_map = None

        bus_obj = param.get('object', 'Incident')
        ret_val, busobid = self._get_busobid(action_result, bus_obj)
        if phantom.is_fail(ret_val):
            return ret_val

        if field_value_map:
            endpoint = CHERWELL_API_GET_OBJECT.format(
                busobid=busobid,
                publicid=public_id
            )

            ret_val, response = self._make_rest_call_helper(endpoint, action_result)
            if phantom.is_fail(ret_val):
                return ret_val

            self._set_field_values(response['fields'], field_value_map)
            ret_val, response = self._make_rest_call_helper(CHERWELL_API_SAVE_OBJECT, action_result, data=response, method="post")
            if phantom.is_fail(ret_val):
                return ret_val
            action_result.add_data(response)

        if vault_id:
            try:
                file_info = Vault.get_file_info(vault_id=vault_id)[0]
            except Exception:
                return action_result.set_status(
                    phantom.APP_ERROR, "Unable to retrieve vault file info"
                )
            try:
                file_bytes = open(file_info['path'], 'rb').read()
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "Unable to read file", e
                )
            endpoint = CHERWELL_API_UPLOAD_ATTACHMENT.format(
                filename=file_info['name'],
                busobid=busobid,
                publicid=public_id,
                offset='0',
                totalsize=file_info['size']
            )
            headers = {'Content-Type': 'application/octet-stream'}
            ret_val, response = self._make_rest_call_helper(
                endpoint, action_result, form_data=file_bytes, headers=headers, method='post'
            )
            if phantom.is_fail(ret_val):
                return ret_val

            summary = action_result.update_summary({})
            summary['attachment_id'] = response

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident")

    def _handle_create_ticket(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        description = param['description']
        priority = param['priority']
        public_id = param.get('user_public_id')
        record_id = param.get('user_record_id')

        # Full Name is same customer public id
        if not record_id and public_id:
            ret_val, record_id = self._get_customer_recid(action_result, public_id)
        elif not record_id and not public_id:
            return action_result.set_status(phantom.APP_ERROR, "Must specify either a Record ID or Pubic ID")

        other = param.get('other')
        if other:
            try:
                other_dict = json.loads(other)
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "Error loading JSON Object", e
                )
        else:
            other_dict = {}

        # First we need to get the object ID for an "Incident"
        bus_obj = param.get('object', 'Incident')
        ret_val, busobid_incident = self._get_busobid(action_result, bus_obj)
        if phantom.is_fail(ret_val):
            return ret_val

        body = {
            'busObId': busobid_incident,
            'includeRequired': True,
            'includeAll': True
        }

        # Then we need to get the template for an incident
        ret_val, response = self._make_rest_call_helper(CHERWELL_API_GET_OBJECT_TEMPLATE, action_result, data=body, method="post")
        if phantom.is_fail(ret_val):
            return ret_val

        field_value_map = CaseInsensitiveDict()
        field_value_map['description'] = description
        field_value_map['priority'] = priority
        field_value_map['customerrecid'] = record_id
        field_value_map.update(other_dict)

        fields = response['fields']
        self._set_field_values(fields, field_value_map)

        body = {
            'busObId': busobid_incident,
            'fields': fields
        }

        # After modifying the tempalte, now POST it over
        ret_val, response = self._make_rest_call_helper(CHERWELL_API_SAVE_OBJECT, action_result, data=body, method="post")
        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['id'] = response['busObPublicId']

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Created Ticket")

    def _handle_get_ticket(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        public_id = param['id']
        bus_obj = param.get('object', 'Incident')

        ret_val, busobid = self._get_busobid(action_result, bus_obj)
        if phantom.is_fail(ret_val):
            return ret_val

        endpoint = CHERWELL_API_GET_OBJECT.format(
            busobid=busobid,
            publicid=public_id
        )

        ret_val, response = self._make_rest_call_helper(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        self._mogrify_fields(action_result, response)

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Listed Tickets")

    def _handle_list_tickets(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        bus_obj = param.get('object', 'Incident')
        search_text = param.get('search_text', '')

        ret_val, busobid = self._get_busobid(action_result, bus_obj)
        if phantom.is_fail(ret_val):
            return ret_val

        search_query = {
            'busObIds': [
                busobid
            ],
            'searchText': search_text
        }

        ret_val, response = self._make_rest_call_helper(CHERWELL_API_QUICK_SEARCH_RESULTS, action_result, method="post", data=search_query)
        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Listed Tickets")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'create_ticket':
            ret_val = self._handle_create_ticket(param)

        elif action_id == 'get_ticket':
            ret_val = self._handle_get_ticket(param)

        elif action_id == 'list_tickets':
            ret_val = self._handle_list_tickets(param)

        elif action_id == 'update_ticket':
            ret_val = self._handle_update_ticket(param)

        elif action_id == 'get_attachments':
            ret_val = self._handle_get_attachments(param)

        elif action_id == "get_user":
            ret_val = self._handle_get_user(param)

        elif action_id == "list_users":
            ret_val = self._handle_list_users(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        config = self.get_config()
        self._base_url = config['api_url'].rstrip('/')
        self._username = config['username']
        self._password = config['password']
        self._client_id = config['client_id']
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(argps.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CherwellConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
