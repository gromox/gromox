Gromox
======

Gromox is the central groupware server component of grommunio. It is capable of
serving as a drop-in replacement for Microsoft Exchange. Connectivity
options include RPC/HTTP (Outlook Anywhere), MAPI/HTTP, EWS, IMAP, POP3, an
SMTP-speaking LDA, and a PHP module with a MAPI function subset. Components can
scale-out over multiple hosts.

|shield-agpl| |shield-release| |shield-cov| |shield-loc|

.. |shield-agpl| image:: https://img.shields.io/badge/license-AGPL--3%2E0-green
                 :target: LICENSE.txt
.. |shield-release| image:: https://shields.io/github/v/tag/grommunio/gromox
                    :target: https://github.com/grommunio/gromox/tags
.. |shield-cov| image:: https://img.shields.io/coverity/scan/gromox
                  :target: https://scan.coverity.com/projects/gromox
.. |shield-loc| image:: https://img.shields.io/github/languages/code-size/grommunio/gromox
                :target: https://github.com/grommunio/gromox/

Gromox is modular and consists of a set of components and programs to provide
its feature set. This repository includes a number of manual pages, for which a
rendered version is at `docs.grommunio.com
<https://docs.grommunio.com/man/gromox.7.html>`_.

Instructions for compilation are in `doc/install.rst <doc/install.rst>`_.
There is also other, mostly technical, documentation in the `<doc/>`_ directory.

Gromox relies on other components to provide a sensibly complete mail system,

* Admin API/CLI (Management):
  `grommunio Admin API/CLI <https://github.com/grommunio/admin-api>`_
* Admin Web Interface (Management):
  `grommunio Admin Web <https://github.com/grommunio/admin-web>`_
* User Web Interface (Web UI):
  `grommunio Web <https://github.com/grommunio/grommunio-web>`_
* Exchange ActiveSync (EAS) (Mobile Devices):
  `grommunio Sync <https://github.com/grommunio/grommunio-sync>`_
* CalDAV & CardDAV (Interoperability with Clients):
  `grommunio DAV <https://github.com/grommunio/grommunio-dav>`_
* a mail transfer agent like Postfix, Exim, and more
* mail security solutions like rspamd and others (commercial ones included)

The grommunio Appliance ships these essentials and has a ready-to-run
installation of Gromox.


Support
=======

Support is available through grommunio GmbH and its partners.
See https://grommunio.com/ for details. A community forum is
at `<https://community.grommunio.com/>`_.

The source code repository and technical issue tracker can be found at
`<https://github.com/grommunio/gromox>`_.

For direct contact and supplying information about a security-related
responsible disclosure, contact `dev@grommunio.com <dev@grommunio.com>`_.


Standards and protocols
=======================

See `<doc/protocols.rst>`_ for a discussion.


Contributing
============

* https://docs.github.com/en/get-started/quickstart/contributing-to-projects
* Alternatively, upload commits to a git store of your choosing, or export the
  series as a patchset using `git format-patch
  <https://git-scm.com/docs/git-format-patch>`_, then convey the git
  link/patches through our direct contact address (above).

Coding and social style
-----------------------

When in Rome, do as the Romans do.

Source layout
-------------

* ``exch``/:

  * ``emsmdb/``: Decoder for EMSMDB/OXCROPS calls (good starting
    point/grepable keyword: ``rop_ext_pull(EXT_PULL &x, ROP_BUFFER &r)``
    function) and handler entrypoint for these calls (gsp.:
    ``rop_dispatch``)

  * ``ews/``: Logic for handling EWS requests (gsp.:
    ``EWSPlugin::dispatch``)

  * ``exmdb/``: The *Information Store* server. Decoder for EXRPC calls
    is in ``lib/exmdb_ext.cpp:exmdb_ext_pull_request``; the big case
    ``switch()`` function is autogenerated during *make* into
    ``include/exmdb_dispatch.cpp``; mailbox logic functions begin with
    the grepable substring ``BOOL exmdb_server::``.

  * ``http/``: HTTP server

    * HTTP request parser (gsp.: ``htparse_rdhead``, and
      ``htparse_rdhead_st`` near ``/* met the end of request header
      */``)

    * MSRPC parser (gsp.: ``pdu_processor_input``)

  * ``mh/``: Handler for OXCMAPIHTTP requests. There is little actual
    mailbox logic, since the code forwards to emsmdb/nsp functions.

  * ``midb/``: A support server specifically for
    gromox-imap/gromox-pop3, gsp. ``mail_engine_commands``. Text-based
    input protocol.

  * ``mysql_adaptor/``: User database support functions

  * ``nsp/``: Decoder for OXNSPI requests (gsp.:
    ``exchange_nsp_ndr_pull``), and logic to handle those (gsp.:
    ``exchange_nsp_dispatch``)

  * ``zcore/``: State keeper for requests from PHP-MAPI. Decoder for ZRPC
    requests gsp. ``rpc_parser_dispatch``, and mailbox logic gsp.
    ``ec_error_t zs_``)

  * ``authmgr.cpp``: component for directing authentication between
    MySQL/LDAP

  * ``oxdisco.cpp``: Handler for AutoDiscover requests

* ``lib/``: functions shared on a large scale

  * ``lib/email/``: Parser for e-mail, calendar, contacts (RFC 5322,
    5545, 6350)

  * ``lib/mapi/``: Data structures mostly specific to MAPI

    * ``oxcical.cpp``: Logic for conversion between parsed
      iCalendar and MAPI calendaring items

    * ``oxcmail.cpp``: Logic for conversion between parsed e-mail
      and MAPI messaging items

    * ``oxvcard.cpp``: Logic for conversion between parsed vCards
      and MAPI contact items

* ``mda/``: Message Delivery Agent

  * ``exmdb_local/`` gsp. ``exmdb_local_hook``

  * ``delivery_app/``: Delivery Agent

  * ``smtp/``: SMTP protocol handler of the MDA

* ``mra/``: Message Retrieval Agents (IMAP, POP3); these are midb clients (not
  exrpc clients), gsp. ``imap_parser_dispatch_cmd2`` and
  ``pop3_parser_dispatch_cmd2``.
