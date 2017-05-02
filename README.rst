syslog2stdout
=============

Listen on syslog port (or unix socket) and relay messages to stdout.

This is useful in combination with *Docker*, which relies on
applications logging to stdout/stderr. If the application can only be
configured to log to syslog, this simple daemon comes in handy.

**TL;DR**

Dockerfile::

    CMD ./syslog2stdout /dev/log & /app/that/logs/to/syslog

See also GoSpawn_ which also takes care of spawning the subprocess(es)
and zombie reaping::

    CMD ["/gospawn", "/dev/log", "--", "/app/that/logs/to/syslog"]

.. _GoSpawn: https://github.com/ossobv/gospawn


Problem description
-------------------

When you contain an application with *Docker*, it requires you to
configure stdout (or stderr) as the logging facility. The *Docker*
process reads stdout/stderr from the application and stores it in its
log.

*Apps inside Docker shall not use file-based logging nor shall they use
syslog.*

But some applications don't have an option to select logging to stdout.

The ServerFault thread `make-a-docker-application-write-to-stdout`_
lists possible tricks to make an application log to stdout anyway.

.. _`make-a-docker-application-write-to-stdout`: http://serverfault.com/questions/599103/make-a-docker-application-write-to-stdout

Examples include:

* Configure the file log as ``/dev/stdout`` directly.

* Forward request and error logs to docker log collector::

   RUN ln -sf /dev/stdout /var/log/nginx/access.log
   RUN ln -sf /dev/stderr /var/log/nginx/error.log

* Tail the application log with a separate backgrounded call to
  ``tail(1)`` from a ``run.sh`` wrapper script.

*However, if the application only logs to syslog, the fix is not that
simple.*

A couple of possible fixes spring to mind:

* Install a full fledged syslog server and have it write to stdout.

  *That feels like overkill.*

* Call the application from a wrapper that rewires the ``syslog(3)``
  library call to a custom function that replaces it with a write to
  stdout.

  *This could work, but you'd have to do (thread safe) bookkeeping
  with openlog. But, some applications don't use the libc syslog
  function and write to /dev/log or port 514 directly, so you wouldn't
  fix those.*

* Create a really minimal wrapper daemon that listens on (configurable)
  ``/dev/log`` or UDP port 514 and relays all messages to stdout.

  **syslog2stdout implements this last option.**

A slight improvement would be if it combined with optional `dumb-init`_
support so it could spawn both itself and the real application, and it
could reap parentless children. Let me know if you need that, and I
will consider adding support for it.

.. _`dumb-init`: https://github.com/Yelp/dumb-init


Usage
-----

*syslog2stdout* is a mini-daemon that relays messages written to
``/dev/log`` (or port 514) and writes them to stdout.

Compiling:

.. code-block:: console

    $ cc -O3 -o syslog2stdout syslog2stdout.c

Replace this in your ``Dockerfile``::

    CMD ['/usr/sbin/cron', '-f', '-L', '15']

with this::

    CMD /path/to/syslog2stdout /dev/log & /usr/sbin/cron -f -L 15

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

*Yes, I realise that using bash is not a replacement for an init system.
For proper use, you'll probably want to use supervisord. See the
improvement suggestion at the Problem Description.*

Of course you don't need *Docker* to use it. Perhaps you just want a
really minimal temporary syslog daemon. Maybe you want to know what your
VoIP phones are doing::

    $ sudo ./syslog2stdout 514 | wtimestamp
    2016-12-20 10:41:36+0100: 10.123.10.132:47427: local2.debug: [2]SIP:ICMP Error -1 (0a7b0a0b:5060, 7)
    2016-12-20 10:41:36+0100: 10.123.10.132:47427: local3.debug: RSE_DEBUG: getting alternate from domain:pbx2.example.com
    2016-12-20 10:41:36+0100: 10.123.10.132:47427: local0.info: [2]SIP:RegFailed;Retry in 30s
    2016-12-20 10:41:36+0100: 10.123.10.132:47427: local0.info: [2]SIP:RegFailed;Retry in 30s
    2016-12-20 10:41:39+0100: 10.123.10.132:47427: local0.info: ++++ retry query scaps

Enjoy!

Walter Doekes, OSSO B.V., 2016-2017.
