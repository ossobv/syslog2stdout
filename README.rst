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


How?
----

Compile:

.. code-block:: console

    $ cc -O3 -o syslog2stdout syslog2stdout.c

Replace this in your ``Dockerfile``::

    CMD ['/usr/sbin/cron', '-f']

with this::

    CMD /path/to/syslog2stdout & /usr/sbin/cron -f

Your Docker job now looks like this::

    \_ docker-containerd-shim HASH /var/run/docker/libcontainerd/HASH docker-runc
        \_ /bin/sh -c ./syslog2stdout /dev/log & /usr/sbin/cron -f -L 15
            \_ ./syslog2stdout /dev/log
            \_ /usr/sbin/cron -f -L 15

And the logging works as expected:

.. code-block:: console

    $ docker logs -t cron
    2016-12-19T21:56:32Z cron.info: cron[8]: (CRON) INFO (pidfile fd = 3)
    2016-12-19T21:56:32Z cron.info: cron[8]: (CRON) INFO (Running @reboot jobs)
    2016-12-19T21:57:01Z authpriv.info: CRON[9]: pam_unix(cron:session): session opened for user root by (uid=0)
    2016-12-19T21:57:01Z cron.info: CRON[9]: (root) CMD ([10] frobnicate >/dev/null 2>&1)
    2016-12-19T21:57:01Z cron.info: CRON[9]: (CRON) error (grandchild #10 failed with exit status 127)
    2016-12-19T21:57:01Z cron.info: CRON[9]: (root) END ([10] frobnicate >/dev/null 2>&1)
    2016-12-19T21:57:01Z authpriv.info: CRON[9]: pam_unix(cron:session): session closed for user root
