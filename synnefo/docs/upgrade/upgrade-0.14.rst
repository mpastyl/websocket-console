Upgrade to Synnefo v0.14
^^^^^^^^^^^^^^^^^^^^^^^^

The upgrade to v0.14 consists in three steps:

1. Bring down services and backup databases.

2. Upgrade packages, migrate the databases and configure settings.

3. Register services to astakos and perform a quota-related data migration.

4. Bring up all services.

.. warning::

    It is strongly suggested that you keep separate database backups
    for each service after the completion of each step.

1. Bring web services down, backup databases
============================================

1. All web services must be brought down so that the database maintains a
   predictable and consistent state during the migration process::

    $ service gunicorn stop
    $ service snf-dispatcher stop
    $ service snf-ganeti-eventd stop

2. Backup databases for recovery to a pre-migration state.

3. Keep the database servers running during the migration process


2. Upgrade Synnefo and configure settings
=========================================

2.1 Install the new versions of packages
----------------------------------------

::

    astakos.host$ apt-get install \
                            python-objpool \
                            snf-common \
                            python-astakosclient \
                            snf-django-lib \
                            snf-webproject \
                            snf-branding \
                            snf-astakos-app

    cyclades.host$ apt-get install \
                            python-objpool \
                            snf-common \
                            python-astakosclient \
                            snf-django-lib \
                            snf-webproject \
                            snf-branding \
                            snf-pithos-backend \
                            snf-cyclades-app

    pithos.host$ apt-get install \
                            python-objpool \
                            snf-common \
                            python-astakosclient \
                            snf-django-lib \
                            snf-webproject \
                            snf-branding \
                            snf-pithos-backend \
                            snf-pithos-app \
                            snf-pithos-webclient

    ganeti.node$ apt-get install \
                            python-objpool \
                            snf-common \
                            snf-cyclades-gtools \
                            snf-pithos-backend

.. note::

   Make sure `snf-webproject' has the same version with snf-common

.. note::

   Package `kamaki', installed on all nodes in version 0.13, is not required
   any more and can safely be uninstalled.

.. note::

    Installing the packages will cause services to start. Make sure you bring
    them down again (at least ``gunicorn``, ``snf-dispatcher``)

2.2 Sync and migrate the database
---------------------------------

.. note::

   If you are asked about stale content types during the migration process,
   answer 'no' and let the migration finish.

::

    astakos-host$ snf-manage syncdb
    astakos-host$ snf-manage migrate quotaholder_app 0001 --fake
    astakos-host$ snf-manage migrate quotaholder_app
    astakos-host$ snf-manage migrate im

    cyclades-host$ snf-manage syncdb
    cyclades-host$ snf-manage migrate

    pithos-host$ pithos-migrate upgrade head

2.3 Configure Base URL settings for all services
------------------------------------------------

In order to make all services' URLs configurable and discoverable from
a single endpoint in Astakos through the Openstack Keystone API,
every service has a ``XXXXX_BASE_URL`` setting, or it's old corresponding
setting was renamed to this. Therefore:

* Rename ``ASTAKOS_URL`` setting to ``ASTAKOS_BASE_URL``
  everywhere in your settings, in all nodes and all config files.
  This must point to the top-level Astakos URL.

* In Cyclades settings, rename the ``APP_INSTALL_URL`` setting
  to ``CYCLADES_BASE_URL``. If no such setting has been configured,
  you must set it. It must point to the top-level Cyclades URL.
  Rename ``CYCLADES_ASTAKOS_SERVICE_TOKEN`` to ``CYCLADES_SERVICE_TOKEN``.

* In Pithos settings, introduce a ``PITHOS_BASE_URL`` setting; it must point
  to the top-level Pithos URL. Rename ``PITHOS_QUOTAHOLDER_POOLSIZE``, if
  set, to ``PITHOS_ASTAKOSCLIENT_POOLSIZE``.

* In all 20-<service>-cloudbar.conf files change setting
  ``CLOUDBAR_SERVICES_URL`` to point to ``ASTAKOS_BASE_URL/ui/get_services``,
  where ``ASTAKOS_BASE_URL`` as above. Similarly, set
  ``CLOUDBAR_MENU_URL`` to ``ASTAKOS_BASE_URL/ui/get_menu``.

If two or more services are installed on the same machine, make sure their
base URLs do not clash. You can distinguish them with a suffix, e.g.
``ASTAKOS_BASE_URL = "https://node1.example.com/astakos"`` and
``CYCLADES_BASE_URL = "https://node1.example.com/cyclades"``.

3 Register services and migrate quota
=====================================

You need to register astakos as a component. Moreover you need to register
all services provided by cyclades and pithos.
Running the following script you will be asked to provide the base
installation URL for each component. You will also need to specify the UI
URL for astakos.

The former is the location where each component resides; it should equal
the ``<component_name>_BASE_URL`` as specified in the respective component
settings (see above).

The latter is the URL that appears in the Cloudbar and leads to the
component UI. If you want to follow the default setup, set
the UI URL to ``<base_url>/ui/`` where ``base_url`` is the component's base
URL as explained before.

For example, for Astakos, if
``BASE_URL = https://accounts.example.synnefo.org/astakos``,
then ``UI_URL = https://accounts.example.synnefo.org/astakos/ui/``)::

    astakos-host$ snf-component-register

(ATTENTION: make sure to go to the next step *WITHOUT* running
``snf-manage resource-modify``, suggested at the end of this command)

.. note::

   This command is equivalent to running the following series of commands;
   in each host it exports the respective service definitions, copies the
   exported json file to the astakos host, where it finally imports it:

    .. code-block:: console

       astakos-host$ snf-manage component-add astakos ui_url
       astakos-host$ snf-manage service-export-astakos > astakos.json
       astakos-host$ snf-manage service-import --json astakos.json
       cyclades-host$ snf-manage service-export-cyclades > cyclades.json
       # copy the file to astakos-host
       astakos-host$ snf-manage service-import --json cyclades.json
       pithos-host$ snf-manage service-export-pithos > pithos.json
       # copy the file to astakos-host
       astakos-host$ snf-manage service-import --json pithos.json

Run::

   astakos-host$ snf-manage component-list

to make sure that all UI URLs are set to the correct value (``<base_url>/ui/``
as explained above). If you have changed some ``<component_name>_BASE_URL``
in the previous step, you will need to update the UI URL with::

   snf-manage component-modify <component_name> --url new_ui_url

The limit on the pending project applications is since 0.14 handled as an
Astakos resource, rather than a custom setting. So, as a last step we need
to run::

    astakos-host$ astakos-migrate-0.14

This will prompt you to set this limit (replacing setting
``ASTAKOS_PENDING_APPLICATION_LIMIT``) and then automatically migrate the
user-specific base quota for the new resource ``astakos.pending_app`` using
the deprecated user setting.

You are now done migrating from Synnefo v0.13 to v0.14. Please test your
installation to make sure everything works as expected.

4. Update astakos email notification settings
=============================================

Make sure to update your configuration to include settings refered in the 
updated :ref:`Email delivery configuration <email-configuration>` section 
of the quick installation admin guide. 

5. Bring all services up
========================

After the upgrade is finished, we bring up all services:

.. code-block:: console

    astakos.host  # service gunicorn start
    cyclades.host # service gunicorn start
    pithos.host   # service gunicorn start

    cyclades.host # service snf-dispatcher start
