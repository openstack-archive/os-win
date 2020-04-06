============
Contributing
============

For general information on contributing to OpenStack, please check out the
`contributor guide <https://docs.openstack.org/contributors/>`_ to get started.
It covers all the basics that are common to all OpenStack projects: the accounts
you need, the basics of interacting with our Gerrit review system, how we
communicate as a community, etc.

Below will cover the more project specific information you need to get started
with os-win.

Communication
~~~~~~~~~~~~~
.. This would be a good place to put the channel you chat in as a project; when/
   where your meeting is, the tags you prepend to your ML threads, etc.

We recommend using the standard communication channels, such as the OpenStack
mailing list or IRC channels. The official IRC channel (#openstack-hyper-v) is
not archived at the moment, so we recommend using #openstack-dev.

Please include one of the following tags when using the OpenStack mailing
list:

* winstackers
* windows
* hyper-v

Feel free to reach out to the Winstackers PTL or other core members.

Contacting the Core Team
~~~~~~~~~~~~~~~~~~~~~~~~
.. This section should list the core team, their irc nicks, emails, timezones
   etc. If all this info is maintained elsewhere (i.e. a wiki), you can link to
   that instead of enumerating everyone here.

The Winstackers core team is composed of:

* Lucian Petrut <lpetrut@cloudbasesolutions.com> (lpetrut)
* Claudiu Belu <cbelu@cloudbasesolutions.com> (claudiub)
* Alessandro Pilotti <apilotti@cloudbasesolutions.com> (apilotti)

New Feature Planning
~~~~~~~~~~~~~~~~~~~~
.. This section is for talking about the process to get a new feature in. Some
   projects use blueprints, some want specs, some want both! Some projects
   stick to a strict schedule when selecting what new features will be reviewed
   for a release.

If you want to propose a new feature, we recommend `filing a blueprint
<https://blueprints.launchpad.net/os-win>`__ and then contacting the core team.

Once the feature is approved, please propose the patches on Gerrit, following
the Openstack contributor guide.

Task Tracking
~~~~~~~~~~~~~
.. This section is about where you track tasks- launchpad? storyboard? is there
   more than one launchpad project? what's the name of the project group in
   storyboard?

We track our tasks in `Launchpad <https://bugs.launchpad.net/os-win>`__.

Reporting a Bug
~~~~~~~~~~~~~~~
.. Pretty self explanatory section, link directly to where people should report
   bugs for your project.

You found an issue and want to make sure we are aware of it? You can do so on
`Launchpad <https://bugs.launchpad.net/os-win/+filebug>`__.
More info about Launchpad usage can be found on `OpenStack docs page
<https://docs.openstack.org/contributors/common/task-tracking.html#launchpad>`_.

Getting Your Patch Merged
~~~~~~~~~~~~~~~~~~~~~~~~~
.. This section should have info about what it takes to get something merged. Do
   you require one or two +2's before +W? Do some of your repos require unit
   test changes with all patches? etc.

Changes proposed to os-win generally require two ``Code-Review +2`` votes from
os-win core reviewers before merging. In case of trivial patches and urgent
bug fixes, this rule is sometimes ignored.

Project Team Lead Duties
~~~~~~~~~~~~~~~~~~~~~~~~
.. this section is where you can put PTL specific duties not already listed in
   the common PTL guide (linked below), or if you already have them written
   up elsewhere you can link to that doc here.

All common PTL duties are enumerated in the `PTL guide
<https://docs.openstack.org/project-team-guide/ptl.html>`_.
