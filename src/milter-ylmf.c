/*
 * MILTER-YLMF -- A popular script-kiddie tool to perform dictionary attacks
 * against SMTP mail servers uses a EHLO ylmf-pc before attempting a login.
 * This milter detects this HELO message, and instructs sendmail to reject
 * all future requests.
 *
 * Author:	David L. Cathey
 * 		Montagar Software, Inc.
 * 		POBox 260772
 * 		Plano, TX 75026-0772
 *
 * References:
 * 	https://www.milter.org/developers
 */
#include	"../config.h"
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<memory.h>
#include	<strings.h>
#include	<sys/types.h>
#include	<sysexits.h>
#include	<netinet/in.h>
#include	<netdb.h>
#include	<arpa/nameser.h>
#include	<libmilter/mfapi.h>
#include	<syslog.h>
#include	<pthread.h>

#define 	MILTER_SOCKET	"/var/run/milter-ylmf.sock"
#define		MILTER_NAME	PACKAGE_STRING

/*
 * Our Milter private structure.  A flag to indicate we want to reject/tempfail the
 * message, and keep the host and helo for logging purposes.
 */
struct nameserver {
	int	flag ;
	char	host[512] ;
	char	helo[512] ;
	char	rcpt[512] ;
	char	from[512] ;
} ;

sfsistat mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *addr)
{
	struct nameserver *mp = malloc(sizeof(struct nameserver)) ;

	// Initialize our connection-specific context, and grab the Hostname
	memset(mp, '\0', sizeof(struct nameserver)) ;
	strncpy(mp->host, hostname, sizeof(mp->host)-1) ;
	smfi_setpriv(ctx, mp) ;
	return(SMFIS_CONTINUE) ;
}

sfsistat mlfi_helo(SMFICTX *ctx, char *helohost)
{
	char			*p ;
	int			status = SMFIS_CONTINUE ;
	struct nameserver	*mp = smfi_getpriv(ctx) ;

	// Note that we test for HELO being 'ylmf-pc', since this has 
	// been seen in a lot of places trying to brute-force accounts on
	// SMTP servers.  If found, we force reject on the reset of the 
	// connection.
	strncpy(mp->helo, helohost, sizeof(mp->helo)-1) ;
	if(strcmp(mp->helo, "ylmf-pc") == 0) {
		syslog(LOG_INFO, "Reject ylmf-pc: Host=%s", mp->host) ;
		status = SMFIS_REJECT ;
	}
	return(status) ;
}

sfsistat mlfi_close(SMFICTX *ctx)
{
	struct nameserver	*mp = smfi_getpriv(ctx) ;
	int			status = SMFIS_CONTINUE ;

	// We are done with the connection, so free up our context
	if(mp != NULL) {
		free(mp) ;
		smfi_setpriv(ctx, NULL) ;
	}
	return(status) ;
}

sfsistat mlfi_abort(SMFICTX *ctx)
{
	struct nameserver	*mp = smfi_getpriv(ctx) ;
	int			status = SMFIS_CONTINUE ;

	// Do nothing here at this time...
	return(status) ;
}

struct smfiDesc smilter =
{
	"nsmilter",			/* Milter name */
	SMFI_VERSION,			/* Version Code */
	SMFIF_ADDHDRS,			/* Milter Flags */
	mlfi_connect,			/* initialize connection */
	mlfi_helo,			/* SMTP HELO command filter */
	NULL,				/* MAIL FROM command filter */
	NULL,				/* RCPT TO command filter */
	NULL,				/* Header filter */
	NULL,				/* End of Headers indicator */
	NULL,				/* Body Block Filter */
	NULL,				/* End of Message indicator */
	mlfi_abort,			/* Message Aborted */
	mlfi_close			/* shutdown connection */
} ;

main(int argc, char **argv)
{
	int	sts ;

//	Set up the Milter socket
	unlink(MILTER_SOCKET) ;
	smfi_setconn(MILTER_SOCKET) ;

	openlog(PACKAGE_NAME, LOG_PID, LOG_MAIL) ;
	syslog(LOG_INFO, "%s Initializing...", PACKAGE_STRING) ;

//	Register our milter callbacks
	if(smfi_register(smilter) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_register failed\n", argv[0]) ;
		exit(EX_UNAVAILABLE) ;
	}

//	And away we go!
	sts = smfi_main() ;
	closelog() ;
	return sts ;
}	
