======
os-win
======

Windows / Hyper-V library for OpenStack projects.

This library contains Windows / Hyper-V specific code commonly used in
OpenStack projects. The library can be used in any other OpenStack projects
where it is needed.

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/os-win
* Source: http://git.openstack.org/cgit/openstack/os-win
* Bugs: http://bugs.launchpad.net/os-win


How to Install
--------------

os-win is released on Pypi, meaning that it can be installed and upgraded via
pip. To install os-win, run the following command:

::

    pip install os-win

To upgrade os-win, run the following command:

::

    pip install -U os-win

Note that the first OpenStack release to use os-win is Mitaka. Previous
releases do not benefit from this library.

Tests
-----

You will have to install the test dependencies first to be able to run the
tests.

::

    C:\os_win> pip install -r requirements.txt
    C:\os_win> pip install -r test-requirements.txt

You can run the unit tests with the following command.

::

    C:\os_win> nosetests os_win\tests


How to contribute
-----------------

To contribute to this project, please go through the following steps.

1. Clone the project and keep your working tree updated.
2. Make modifications on your working tree.
3. Run unit tests.
4. If the tests pass, commit your code.
5. Submit your code via ``git review``.
6. Check that Jenkins and the Microsoft Hyper-V CI pass on your patch.
7. If there are issues with your commit, ammend, and submit it again via
   ``git review``.
8. Wait for the patch to be reviewed.


Features
--------

os-win is currently used in the following OpenStack projects:

* nova
* cinder
* compute-hyperv
* networking-hyperv
* ceilometer
* os-brick
