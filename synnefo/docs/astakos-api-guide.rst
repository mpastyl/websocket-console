Astakos API
===========

This is Astakos API guide.

Overview
--------


Astakos service co-ordinates the access to resources (and the subsequent
permission model) and acts as the single point of registry and entry to the
GRNET cloud services.

This document's goals is to describe the APIs to the outer world.
Make sure you have read the :ref:`astakos` general architecture first.

Document Revisions
^^^^^^^^^^^^^^^^^^

=========================  ================================
Revision                   Description
=========================  ================================
0.14 (June 03, 2013)       Remove endpoint listing
0.14 (May 28, 2013)        Extend token api with authenticate call
0.14 (May 23, 2013)        Extend api to list endpoints
0.14 (May 14, 2013)        Do not serve user quotas in :ref:`authenticate-api-label`
0.14 (May 02, 2013)        Change URIs (keep also the old ones until the next version)
0.13 (January 21, 2013)    Extend api to export user presentation & quota information.
0.6 (June 06, 2012)        Split service and user API.
0.1 (Feb 10, 2012)         Initial release.
=========================  ================================

Get Services
^^^^^^^^^^^^

Returns a json formatted list containing information about the supported cloud services.

============================= =========  ==================
Uri                           Method     Description
============================= =========  ==================
``/ui/get_services``          GET        Get cloud services
============================= =========  ==================

Example reply:

::

    [{"url": "/", "icon": "home-icon.png", "name": "grnet cloud", "id": "1"},
    {"url": "/okeanos.html", "name": "~okeanos", "id": "2"},
    {"url": "/ui/", "name": "pithos", "id": "3"}]


Get Menu
^^^^^^^^

Returns a json formatted list containing the cloud bar links.

========================= =========  ==================
Uri                       Method     Description
========================= =========  ==================
``/ui/get_menu``          GET        Get cloud bar menu
========================= =========  ==================

Example reply if request user is not authenticated:

::

    [{"url": "/ui/", "name": "Sign in"}]

Example reply if request user is authenticated:

::

    [{"url": "/ui/", "name": "user@example.com"},
    {"url": "/ui/landing", "name": "Dashboard"},
    {"url": "/ui/logout", "name": "Sign out"}]


User API Operations
--------------------

The operations described in this chapter allow users to authenticate themselves, send feedback and get user uuid/displayname mappings.

All the operations require a valid user token.

.. _authenticate-api-label:

Authenticate
^^^^^^^^^^^^

Authenticate API requests require a token. An application that wishes to connect to Astakos, but does not have a token, should redirect the user to ``/login``. (see :ref:`authentication-label`)

============================== =========  ==================
Uri                            Method     Description
============================== =========  ==================
``/account/v1.0/authenticate`` GET        Authenticate user using token
============================== =========  ==================

|

====================  ===========================
Request Header Name   Value
====================  ===========================
X-Auth-Token          User authentication token
====================  ===========================

Extended information on the user serialized in the json format will be returned:

===========================  ============================
Name                         Description
===========================  ============================
displayname                     User displayname
uuid                         User unique identifier
email                        List with user emails
name                         User full name
auth_token_created           Token creation date
auth_token_expires           Token expiration date
usage                        List of user resource usage (if usage request parameter is present)
===========================  ============================

Example reply:

::

  {"id": "12",
  "displayname": "user@example.com",
  "uuid": "a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8",
  "email": "[user@example.com]",
  "name": "Firstname Lastname",
  "auth_token_created": "Wed, 30 May 2012 10:03:37 GMT",
  "auth_token_expires": "Fri, 29 Jun 2012 10:03:37 GMT"}

|

=========================== =====================
Return Code                 Description
=========================== =====================
204 (No Content)            The request succeeded
400 (Bad Request)           Method not allowed or no user found
401 (Unauthorized)          Missing token or inactive user or penging approval terms
500 (Internal Server Error) The request cannot be completed because of an internal error
=========================== =====================

.. warning:: The service is also available under ``/ui/authenticate``.
     It  will be removed in the next version.


Send feedback
^^^^^^^^^^^^^

Post user feedback.

========================== =========  ==================
Uri                        Method     Description
========================== =========  ==================
``/account/v1.0/feedback`` POST       Send feedback
========================== =========  ==================

|

====================  ============================
Request Header Name   Value
====================  ============================
X-Auth-Token          User authentication token
====================  ============================

|

======================  =========================
Request Parameter Name  Value
======================  =========================
feedback_msg            Feedback message
feedback_data           Additional information about service client status
======================  =========================

|

=========================== =====================
Return Code                 Description
=========================== =====================
200 (OK)                    The request succeeded
502 (Bad Gateway)           Send feedback failure
400 (Bad Request)           Method not allowed or invalid message data
401 (Unauthorized)          Missing or expired user token
500 (Internal Server Error) The request cannot be completed because of an internal error
=========================== =====================

.. warning:: The service is also available under ``/feedback``.
     It  will be removed in the next version.

Get User catalogs
^^^^^^^^^^^^^^^^^

Return a json formatted dictionary containing information about a specific user

=============================== =========  ==================
Uri                             Method     Description
=============================== =========  ==================
``/account/v1.0/user_catalogs`` POST       Get 2 catalogs containing uuid to displayname mapping and the opposite
=============================== =========  ==================

|

====================  ============================
Request Header Name   Value
====================  ============================
X-Auth-Token          User authentication token
====================  ============================

|

The request body is a json formatted dictionary containing a list with uuids and another list of displaynames to translate.

Example request content:

::

  {"displaynames": ["user1@example.com", "user2@example.com"],
   "uuids":["ff53baa9-c025-4d56-a6e3-963db0438830", "a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8"]}

Example reply:

::

  {"displayname_catalog": {"user1@example.com": "a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8",
                           "user2@example.com": "816351c7-7405-4f26-a968-6380cf47ba1f"},
  'uuid_catalog': {"a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8": "user1@example.com",
                   "ff53baa9-c025-4d56-a6e3-963db0438830": "user2@example.com"}}


|

=========================== =====================
Return Code                 Description
=========================== =====================
200 (OK)                    The request succeeded
400 (Bad Request)           Method not allowed or request body is not json formatted
401 (Unauthorized)          Missing or expired or invalid user token
500 (Internal Server Error) The request cannot be completed because of an internal error
=========================== =====================

.. warning:: The service is also available under ``/user_catalogs``.
     It  will be removed in the next version.

Service API Operations
----------------------

The operations described in this chapter allow services to get user uuid/displayname mappings.

All the operations require a valid service token.

Get User catalogs
^^^^^^^^^^^^^^^^^

Return a json formatted dictionary containing information about a specific user

======================================= =========  ==================
Uri                                     Method     Description
======================================= =========  ==================
``/account/v1.0/service/user_catalogs`` POST       Get 2 catalogs containing uuid to displayname mapping and the opposite
======================================= =========  ==================

|

====================  ============================
Request Header Name   Value
====================  ============================
X-Auth-Token          Service authentication token
====================  ============================

|

The request body is a json formatted dictionary containing a list with uuids and another list of displaynames to translate.
If instead of list null is passed then the response contains the information for all the system users (For discretion purposes
this behavior is **not** exposed in the respective call of the User API).

Example request content:

::

  {"displaynames": ["user1@example.com", "user2@example.com"],
   "uuids":["ff53baa9-c025-4d56-a6e3-963db0438830", "a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8"]}

Example reply:

::

  {"displayname_catalog": {"user1@example.com": "a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8",
                           "user2@example.com": "816351c7-7405-4f26-a968-6380cf47ba1f"},
  'uuid_catalog': {"a9dc21d2-bcb2-4104-9a9e-402b7c70d6d8": "user1@example.com",
                   "ff53baa9-c025-4d56-a6e3-963db0438830": "user2@example.com"}}


|

=========================== =====================
Return Code                 Description
=========================== =====================
200 (OK)                    The request succeeded
400 (Bad Request)           Method not allowed or request body is not json formatted
401 (Unauthorized)          Missing or expired or invalid service token
500 (Internal Server Error) The request cannot be completed because of an internal error
=========================== =====================

.. warning:: The service is also available under ``/service/api/user_catalogs``.
     It  will be removed in the next version.

Tokens API Operations
----------------------

Authenticate
^^^^^^^^^^^^

Fallback call which receives the user token or the user uuid/token pair and
returns back the token as well as information about the token holder and the
services he/she can access.
If not request body is provided (the request content length is missing or
equals to 0) the response contains only non authentication protected
information (the service catalog).

========================================= =========  ==================
Uri                                       Method     Description
========================================= =========  ==================
``/identity/v2.0/tokens/``                POST       Checks whether the provided token is valid and conforms with the provided uuid (if present) and returns back information about the user
========================================= =========  ==================

The input should be json formatted.

Example request:

::

    {
        "auth":{
            "token":{
                "id":"CDEe2k0T/HdiJWBMMbHyOA"
            },
            "tenantName":"c18088be-16b1-4263-8180-043c54e22903"
        }
    }

or

::

    {
        "auth":{
            "passwordCredentials":{
                "username":"c18088be-16b1-4263-8180-043c54e22903",
                "password":"CDEe2k0T/HdiJWBMMbHyOA"
            },
            "tenantName":"c18088be-16b1-4263-8180-043c54e22903"
        }
    }


The tenantName in the above requests is optional.

The response is json formatted unless it is requested otherwise via format
request parameter or Accept header.

Example json response:

::

    {"access": {
        "token": {
            "expires": "2013-06-19T15:23:59.975572+00:00",
            "id": "CDEe2k0T/HdiJWBMMbHyOA==",
            "tenant": {
                "id": "c18088be-16b1-4263-8180-043c54e22903",
                "name": "Firstname Lastname"
            }
        },
        "serviceCatalog": [
            {"endpoints_links": [],
             "endpoints": [{
                "SNF:uiURL": "https://accounts.example.synnefo.org/ui",
                "versionId": "v1.0",
                "publicURL": "https://accounts.example.synnefo.org/account/v1.0"}],
             "type": "account",
             "name": "astakos_account"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://accounts.example.synnefo.org/ui",
                 "versionId": "v2.0",
                 "publicURL": "https://accounts.example.synnefo.org/account/v2.0"}],
             "type": "identity",
             "name": "astakos_identity"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://cyclades.example.synnefo.org/ui",
                 "versionId": "v2.0",
                 "publicURL": "https://cyclades.example.synnefo.org/cyclades/compute/v2.0"}],
             "type": "compute",
             "name": "cyclades_compute"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://cyclades.example.synnefo.org/ui",
                 "versionId": "v1.0",
                 "publicURL": "https://cyclades.example.synnefo.org/cyclades/vmapi/v1.0"}],
             "type": "cyclades_vmapi",
             "name": "cyclades_vmapi"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://cyclades.example.synnefo.org/ui",
                 "versionId": "v1.0",
                 "publicURL": "https://cyclades.example.synnefo.org/cyclades/image/v1.0"}],
             "type": "image",
             "name": "cyclades_plankton"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://object-store.example.synnefo.org/ui",
                 "versionId": "v2.0",
                 "publicURL": "https://object-store.example.synnefo.org/pithos/public/v2.0"}],
             "type": "public",
             "name": "pithos_public"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://object-store.example.synnefo.org/ui",
                 "versionId": "v1",
                 "publicURL": "https://object-store.example.synnefo.org/pithos/object-store/v1"}],
             "type": "object-store",
             "name": "pithos_object-store"},
            {"endpoints_links": [],
             "endpoints": [{
                 "SNF:uiURL": "https://accounts.example.synnefo.org/ui",
                 "versionId": "",
                 "SNF:webloginURL": "http://localhost:8080/astakos/weblogin"
                 "publicURL": "https://accounts.example.synnefo.org/astakos/weblogin"}],
             "type": "astakos_weblogin",
             "name": "astakos_weblogin"}],
         "user": {
             "roles_links": [],
             "id": "c18088be-16b1-4263-8180-043c54e22903",
             "roles": [{"id": 1, "name": "default"}],
             "name": "Firstname Lastname"}}}

Example xml response:

::

    <?xml version="1.0" encoding="UTF-8"?>

    <access xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns="http://docs.openstack.org/identity/api/v2.0">
        <token id="CDEe2k0T/HdiJWBMMbHyOA==" expires="2013-06-19T15:23:59.975572+00:00">
            <tenant id="c18088be-16b1-4263-8180-043c54e22903" name="Firstname Lastname" />
        </token>
        <user id="c18088be-16b1-4263-8180-043c54e22903" name="Firstname Lastname">
            <roles>
                    <role id="1" name="default"/>
            </roles>
        </user>
        <serviceCatalog>
            <service type="account" name="astakos_account">
                <endpoint  SNF:uiURL="https://accounts.example.synnefo.org/ui"  versionId="v1.0"  publicURL="https://accounts.example.synnefo.org/account/v1.0"  />
            </service>
            <service type="identity" name="astakos_identity">
                <endpoint  SNF:uiURL="https://accounts.example.synnefo.org/ui"  versionId="v2.0"  publicURL="https://accounts.example.synnefo.org/account/v2.0"  />
            </service>
            <service type="compute" name="cyclades_compute">
                <endpoint  SNF:uiURL="https://cyclades.example.synnefo.org/ui"  versionId="v2.0"  publicURL="https://cyclades.example.synnefo.org/cyclades/compute/v2.0"  />
            </service>
            <service type="cyclades_vmapi" name="cyclades_vmapi">
                <endpoint  SNF:uiURL="https://cyclades.example.synnefo.org/ui"  versionId="v1.0"  publicURL="https://cyclades.example.synnefo.org/cyclades/vmapi/v1.0"  />
            </service>
            <service type="image" name="cyclades_plankton">
                <endpoint  SNF:uiURL="https://cyclades.example.synnefo.org/ui"  versionId="v1.0"  publicURL="https://cyclades.example.synnefo.org/cyclades/image/v1.0"  />
            </service>
            <service type="public" name="pithos_public">
                <endpoint  SNF:uiURL="https://object-store.example.synnefo.org/ui"  versionId="v2.0"  publicURL="https://object-store.example.synnefo.org/pithos/public/v2.0"  />
            </service>
            <service type="object-store" name="pithos_object-store">
                <endpoint  SNF:uiURL="https://object-store.example.synnefo.org/ui"  versionId="v1"  publicURL="https://object-store.example.synnefo.org/pithos/object-store/v1"  /> </service>
            <service type="astakos_weblogin" name="astakos_weblogin">
                <endpoint  SNF:uiURL="htftps://accounts.example.synnefo.org/ui"  versionId=""  "SNF:webloginURL": "http://localhost:8080/astakos/weblogin"  publicURL="https://accounts.example.synnefo.org/astakos/weblogin"  />
        </serviceCatalog>
    </access>

|

=========================== =====================
Return Code                 Description
=========================== =====================
200 (OK)                    The request succeeded
400 (Bad Request)           Method not allowed or invalid request format or missing expected input or not consistent tenantName
401 (Unauthorized)          Invalid token or invalid creadentials or tenantName does not comply with the provided token
500 (Internal Server Error) The request cannot be completed because of an internal error
=========================== =====================
