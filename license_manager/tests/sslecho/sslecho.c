/*
 *  Copyright (C) 2022 Modelon AB
 *  Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 * 
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sslecho.h"

static const int server_port = 4433;

typedef unsigned char   bool;
#define true            1
#define false           0

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;


int create_server_socket()
{
    // Adapted from https://github.com/openssl/openssl/blob/93429fc0ce9468242a463ff5878cd53b97e7f13f/demos/sslecho/main.c
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
            < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        // The usual fix when running unit tests is kill the unit test executable (test_mfl_license_check):
        //    kill -9 $(pgrep test_mfl_license_check)
        // Otherwise, to find the process that is already bound to the port in devcontainer, first install the 'socket statistics' (ss) command:
        //     sudo yum install -y iproute 
        // Then to list the process, run this (https://unix.stackexchange.com/a/106562):
        //     ss -nlpt 'sport = :4433'
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}


SSL_CTX* create_server_context()
{
    // Adapted from https://github.com/openssl/openssl/blob/93429fc0ce9468242a463ff5878cd53b97e7f13f/demos/sslecho/main.c
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}


void configure_server_context(SSL_CTX *ctx)
{
    // Adapted from https://github.com/openssl/openssl/blob/93429fc0ce9468242a463ff5878cd53b97e7f13f/demos/sslecho/main.c
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}



/**
 * Returns number of bytes written, or <= 0 on failure.
 */    
static int send_request(SSL *ssl, const char *request)
{
    // Adapted from https://stackoverflow.com/a/41321247
    int len = SSL_write(ssl, request, strlen(request));
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }
    return len;
}

void log_ssl_error()
{
    // Adapted from https://stackoverflow.com/a/41321247
    int error;
    while (error = ERR_get_error()) {
        char *error_string = ERR_error_string(error, 0);
        if (error_string == NULL)
            return;
        fprintf(stderr, "%s\n", error_string);
    }
}

int server_main(int argc, char **argv)
{
    // Adapted from https://github.com/openssl/openssl/blob/93429fc0ce9468242a463ff5878cd53b97e7f13f/demos/sslecho/main.c
    int result;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_ip = NULL;

    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);


    /* Need to know if client or server */
    if (argc < 2) {
        exit(1);
        /* NOTREACHED */
    }

    /* Create context used by server */
    ssl_ctx = create_server_context();


    // printf("We are the server on port: %d\n\n", server_port);

    /* Configure server context with appropriate key files */
    configure_server_context(ssl_ctx);

    /* Create server socket; will bind with server port and listen */
    server_skt = create_server_socket();

    /*
        * Loop to accept clients.
        * Need to implement timeouts on TCP & SSL connect/read functions
        * before we can catch a CTRL-C and kill the server.
        */
    while (server_running) {
        /* Wait for TCP connection from client */
        client_skt = accept(server_skt, (struct sockaddr*) &addr,
                &addr_len);
        if (client_skt < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        /* Client TCP connection accepted */

        /* Create server SSL structure using newly accepted client socket */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            server_running = false;
        } else {
            /* Client SSL connection accepted */
            /* Get message from client; will fail if client closes connection */
            if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                if (rxlen == 0) {
                    printf("Client closed connection\n");
                }
                ERR_print_errors_fp(stderr);
                goto exit;
            }
            /* Insure null terminated input */
            rxbuf[rxlen] = 0;
            /* Look for kill switch */
            if (strcmp(rxbuf, "kill\n") == 0) {
                /* Terminate...with extreme prejudice */
                printf("Server received 'kill' command\n");
                server_running = false;
                break;
            }
            char *jwt_token = getenv("MODELON_LICENSE_USER_JWT");
            if (jwt_token == NULL) {
                fprintf(stderr, "sslecho server: error: environment variable not set: MODELON_LICENSE_USER_JWT");
                goto exit;
            }
            /* Send JWT Token in a HTTP Response*/
            size_t jwt_token_sz = strlen(jwt_token);
            char *http_response = malloc(jwt_token_sz + 1024); // add room for HTTP header
            sprintf(
                http_response,
                "HTTP/1.1 200 OK\r\n"
                "Server: SimpleHTTP/0.6 Python/3.6.8\r\n"
                "Date: Fri, 22 Jul 2022 18:42:00 GMT\r\n"
                "Content-type: text/html; charset=utf-8\r\n"
                "Content-Length: %d\r\n"
                "\r\n"
                "%s",
                jwt_token_sz,
                jwt_token
            );
            if (send_request(ssl, http_response) <= 0) {
                ERR_print_errors_fp(stderr);
            }
            free(http_response);
            /* Terminate after having sent HTTP Response */
            server_running = false;
        }
    }
exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);
    if (server_skt != -1)
        close(server_skt);
    return 0;
}

void sslecho_server_fork()
{
    /* fork server child process */
    pid_t pid=fork();
    if(pid<0) {
        fprintf(stderr, "fork() error");
        exit(1);
    }
    if(pid==0) {
        int exit_status = 1;
        // make child process die after parent exit (https://stackoverflow.com/a/36945270)
        int status = prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (status == -1) {
            fprintf(stderr, "prctl() error");
            exit(1);
        }
        char *server_argv[] = {"sslecho", "s"};
        exit_status = server_main(2, server_argv);
        exit(exit_status);
    }
}
