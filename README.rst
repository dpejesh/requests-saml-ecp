requests SAML2 ECP authentication library
=========================================

Requests is an HTTP library, written in Python, for human beings. This library
adds optional SAML2 ECP authentication.

.. code-block:: pycon

    >>> import requests
    >>> from requests.auth import HTTPBasicAuth
    >>> from requests_saml_ecp import SAMLECPAuth
    >>>
    >>> idp_auth = HTTPBasicAuth('username', 'password')
    >>> sp_auth = SAMLECPAuth("https://idp.example.org/idp/profile/SAML2/SOAP/ECP", idp_auth)
    >>>
    >>> r = requests.get("http://sp.example.org", auth=sp_auth)
    ...
