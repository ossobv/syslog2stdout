syslog2stdout
=============

Listen on syslog port/socket and relay messages to stdout for Docker log to consume.

See also: 
http://serverfault.com/questions/599103/make-a-docker-application-write-to-stdout

Problem
-------

Dockerized apps should write to stdout/stderr. If there are dockerized
apps that will only write to syslog, there don't appear to be easy
fixes.

For example, the Vixie cron 3.0 on my Ubuntu Xenial has three options:
foreground or daemonize, something about LSB-compliant filenames and the
log *level*. There appears to be no setting to change the logging to
write to stdout/stderr.


Solution
--------

A mini-daemon that relays messages written to ``/dev/log`` (or port 514)
and writes them to stdout.


How
---

Compile.

.. code-block:: console

    $ cc -O3 -o syslog2stdout syslog2stdout.c

Replace this in your ``Dockerfile``::

    CMD ['/usr/sbin/cron', '-f']

with this::

    CMD /path/to/syslog2stdout & /usr/sbin/cron -f
