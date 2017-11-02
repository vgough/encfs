/*	$OpenBSD: readpassphrase.c,v 1.12 2001/12/15 05:41:00 millert Exp $
 */

/*
 * Copyright (c) 2000 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static const char rcsid[] =
    "$OpenBSD: readpassphrase.c,v 1.12 2001/12/15 05:41:00 millert Exp $";
#endif /* LIBC_SCCS and not lint */

//#include "includes.h"

#ifndef HAVE_READPASSPHRASE

#include "readpassphrase.h"

#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <paths.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#ifdef TCSASOFT
#define _T_FLUSH (TCSAFLUSH | TCSASOFT)
#else
#define _T_FLUSH (TCSAFLUSH)
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#if !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#define _POSIX_VDISABLE VDISABLE
#endif

static volatile sig_atomic_t signo;

static void handler(int);

char *readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags) {
  ssize_t nr;
  int input, output, save_errno;
  char ch, *p, *end;
  struct termios term, oterm;
  struct sigaction sa, saveint, savehup, savequit, saveterm;
  struct sigaction savetstp, savettin, savettou;

  /* I suppose we could alloc on demand in this case (XXX). */
  if (bufsiz == 0) {
    errno = EINVAL;
    return (nullptr);
  }

restart:
  /*
   * Read and write to /dev/tty if available.  If not, read from
   * stdin and write to stderr unless a tty is required.
   */
  if ((input = output = open(_PATH_TTY, O_RDWR)) == -1) {
    if ((flags & RPP_REQUIRE_TTY) != 0) {
      errno = ENOTTY;
      return (nullptr);
    }
    input = STDIN_FILENO;
    output = STDERR_FILENO;
  }

  /*
   * Catch signals that would otherwise cause the user to end
   * up with echo turned off in the shell.  Don't worry about
   * things like SIGALRM and SIGPIPE for now.
   */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* don't restart system calls */
  sa.sa_handler = handler;
  (void)sigaction(SIGINT, &sa, &saveint);
  (void)sigaction(SIGHUP, &sa, &savehup);
  (void)sigaction(SIGQUIT, &sa, &savequit);
  (void)sigaction(SIGTERM, &sa, &saveterm);
  (void)sigaction(SIGTSTP, &sa, &savetstp);
  (void)sigaction(SIGTTIN, &sa, &savettin);
  (void)sigaction(SIGTTOU, &sa, &savettou);

  /* Turn off echo if possible. */
  if (tcgetattr(input, &oterm) == 0) {
    memcpy(&term, &oterm, sizeof(term));
    if ((flags & RPP_ECHO_ON) == 0) {
      term.c_lflag &= ~(ECHO | ECHONL);
    }
#ifdef VSTATUS
    if (term.c_cc[VSTATUS] != _POSIX_VDISABLE) {
      term.c_cc[VSTATUS] = _POSIX_VDISABLE;
    }
#endif
    (void)tcsetattr(input, _T_FLUSH, &term);
  } else {
    memset(&term, 0, sizeof(term));
    memset(&oterm, 0, sizeof(oterm));
  }

  if (write(output, prompt, strlen(prompt)) != -1) {
    //dummy test to get rid of warn_unused_result compilation warning
  }
  end = buf + bufsiz - 1;
  for (p = buf; (nr = read(input, &ch, 1)) == 1 && ch != '\n' && ch != '\r';) {
    if (p < end) {
      if ((flags & RPP_SEVENBIT) != 0) {
        ch &= 0x7f;
      }
      if (isalpha(ch) != 0) {
        if ((flags & RPP_FORCELOWER) != 0) {
          ch = tolower(ch);
        }
        if ((flags & RPP_FORCEUPPER) != 0) {
          ch = toupper(ch);
        }
      }
      *p++ = ch;
    }
  }
  *p = '\0';
  save_errno = errno;
  if ((term.c_lflag & ECHO) == 0u) {
    if (write(output, "\n", 1) != -1) {
      //dummy test to get rid of warn_unused_result compilation warning
    }
  }

  /* Restore old terminal settings and signals. */
  if (memcmp(&term, &oterm, sizeof(term)) != 0) {
    (void)tcsetattr(input, _T_FLUSH, &oterm);
  }
  (void)sigaction(SIGINT, &saveint, nullptr);
  (void)sigaction(SIGHUP, &savehup, nullptr);
  (void)sigaction(SIGQUIT, &savequit, nullptr);
  (void)sigaction(SIGTERM, &saveterm, nullptr);
  (void)sigaction(SIGTSTP, &savetstp, nullptr);
  (void)sigaction(SIGTTIN, &savettin, nullptr);
  (void)sigaction(SIGTTOU, &savettou, nullptr);
  if (input != STDIN_FILENO) {
    (void)close(input);
  }

  /*
   * If we were interrupted by a signal, resend it to ourselves
   * now that we have restored the signal handlers.
   */
  if (signo != 0) {
    kill(getpid(), signo);
    switch (signo) {
      case SIGTSTP:
      case SIGTTIN:
      case SIGTTOU:
        signo = 0;
        goto restart;
    }
  }

  errno = save_errno;
  return (nr == -1 ? nullptr : buf);
}
#endif /* HAVE_READPASSPHRASE */

#if 0
char *
getpass(const char *prompt)
{
	static char buf[_PASSWORD_LEN + 1];

	return(readpassphrase(prompt, buf, sizeof(buf), RPP_ECHO_OFF));
}
#endif

static void handler(int s) { signo = s; }
