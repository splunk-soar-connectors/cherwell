# File: cherwell_consts.py
#
# Copyright (c) 2017-2019 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
CHERWELL_API_TOKEN = '/token'
CHERWELL_API_OBJ_SUMMARY = '/api/V1/getbusinessobjectsummary/busobname/{busobname}'
CHERWELL_API_QUICK_SEARCH_RESULTS = '/api/V1/getquicksearchresults'
CHERWELL_API_GET_OBJECT = '/api/V1/getbusinessobject/busobid/{busobid}/publicid/{publicid}'
CHERWELL_API_GET_OBJECT_TEMPLATE = '/api/V1/GetBusinessObjectTemplate'
CHERWELL_API_SAVE_OBJECT = '/api/V1/SaveBusinessObject'
CHERWELL_API_GET_OBJECT_SCHEMA = '/api/V1/getbusinessobjectschema/busobid/{busobid}'
CHERWELL_API_GET_SEARCH_RESULT = '/api/V1/getsearchresults'
CHERWELL_API_UPLOAD_ATTACHMENT = '/api/V1/uploadbusinessobjectattachment/filename/{filename}/busobid/{busobid}/publicid/{publicid}/offset/{offset}/totalsize/{totalsize}'
CHERWELL_GET_ATTACHMENTS = '/api/V1/getbusinessobjectattachments/'
CHERWELL_GET_ATTACHMENT = '/api/V1/getbusinessobjectattachment/attachmentid/{attachmentid}/busobid/{busobid}/busobrecid/{busobrecid}'
CHERWELL_GET_USER_RECORD_ID = '/api/V1/getuserbyrecid/recid/{recid}'
CHERWELL_GET_USER_PUBLIC_ID = '/api/V1/getuserbypublicid/publicid/{publicid}'
CHERWELL_LIST_USERS = '/api/V1/getlistofusers'
