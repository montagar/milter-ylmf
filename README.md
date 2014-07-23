milter-ylmf
==========

 A sendmail milter to reject any commands from a host that HELO's
as ylmf-pc, which is commonly seen as performing a dictionary attack on the SMTP
server.

This was originally part of me playing around with the milter interface.

Author:	David L. Cathey
	c/o Montagar Software, Inc.
	P.O.Box 260772
	Plano, TX 750226-0772

Copyright (c) 2014, Montagar Software, Inc.

Licensing
----------

See COPYING  for license information.

Prerequisites
--------------

	sendmail

Installation
------------

	./configure --prefix=/usr

	Add a similar line to /etc/mail/sendmail.mc:

		INPUT_MAIL_FILTER(`milter-ylmf', `S=unix:/var/run/milter-ylmf.sock, T=S:30s;R:30s;E:5m')

	Add the following file to /etc/init:

		milter-ylmf.conf

	Rebuild sendmail.cf, and restart:

		make
		systemctl restart sendmail

	This file will insure the milter is started before sendmail is started

	
