#ifndef _H_LISTENER_
#define _H_LISTENER_

void listener_init(int port, int port_ssl);

int listener_run();

int listerner_trigger_accept();

void listener_free();

int listener_stop();

#endif
