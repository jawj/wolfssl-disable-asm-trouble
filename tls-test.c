/* This file is based on WolfSSL example code: client-tls-callback.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * That file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* socket includes */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

unsigned char rootCert[] =  // ISRG Root X1
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n";

int my_IORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx) {
  /* By default, ctx will be a pointer to the file descriptor to read from.
   * This can be changed by calling wolfSSL_SetIOReadCtx(). */
  int sockfd = *(int*)ctx;
  int recvd;

  /* Receive message from socket */
  if ((recvd = recv(sockfd, buff, sz, 0)) == -1) {
    /* error encountered. Be responsible and report it in wolfSSL terms */

    fprintf(stderr, "IO RECEIVE ERROR: ");
    switch (errno) {
#if EAGAIN != EWOULDBLOCK
      case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
#endif
      case EWOULDBLOCK:
        if (!wolfSSL_dtls(ssl) || wolfSSL_get_using_nonblock(ssl)) {
          fprintf(stderr, "would block\n");
          return WOLFSSL_CBIO_ERR_WANT_READ;
        } else {
          fprintf(stderr, "socket timeout\n");
          return WOLFSSL_CBIO_ERR_TIMEOUT;
        }
      case ECONNRESET:
        fprintf(stderr, "connection reset\n");
        return WOLFSSL_CBIO_ERR_CONN_RST;
      case EINTR:
        fprintf(stderr, "socket interrupted\n");
        return WOLFSSL_CBIO_ERR_ISR;
      case ECONNREFUSED:
        fprintf(stderr, "connection refused\n");
        return WOLFSSL_CBIO_ERR_WANT_READ;
      case ECONNABORTED:
        fprintf(stderr, "connection aborted\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
      default:
        fprintf(stderr, "general error\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
  } else if (recvd == 0) {
    puts("Connection closed");
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  }

  printf("%s", "recv:");
  for (int i = 0; i < sz; i++) printf(" %02x", (unsigned char)buff[i]);
  puts("");

  /* successful receive */
  printf("received %d bytes from %i\n\n", sz, sockfd);
  return recvd;
}

int my_IOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx) {
  /* By default, ctx will be a pointer to the file descriptor to write to.
   * This can be changed by calling wolfSSL_SetIOWriteCtx(). */
  int sockfd = *(int*)ctx;
  int sent;

  printf("%s", "send:");
  for (int i = 0; i < sz; i++) printf(" %02x", (unsigned char)buff[i]);
  puts("");

  /* Receive message from socket */
  if ((sent = send(sockfd, buff, sz, 0)) == -1) {
    /* error encountered. Be responsible and report it in wolfSSL terms */

    fprintf(stderr, "IO SEND ERROR: ");
    switch (errno) {
#if EAGAIN != EWOULDBLOCK
      case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
#endif
      case EWOULDBLOCK:
        fprintf(stderr, "would block\n");
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
      case ECONNRESET:
        fprintf(stderr, "connection reset\n");
        return WOLFSSL_CBIO_ERR_CONN_RST;
      case EINTR:
        fprintf(stderr, "socket interrupted\n");
        return WOLFSSL_CBIO_ERR_ISR;
      case EPIPE:
        fprintf(stderr, "socket EPIPE\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
      default:
        fprintf(stderr, "general error\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
  } else if (sent == 0) {
    puts("Connection closed");
    return 0;
  }

  /* successful send */
  printf("sent %d bytes to %i\n\n", sz, sockfd);
  return sent;
}

int main(int argc, char** argv) {
  int ret;
  int sockfd = SOCKET_INVALID;
  struct sockaddr_in servAddr;
  char buff[256];
  size_t len;

  /* declare wolfSSL objects */
  WOLFSSL_CTX* ctx = NULL;
  WOLFSSL* ssl = NULL;

  /* Check for proper calling convention */
  if (argc != 4) {
    printf("usage: %s <IPv4 address> <port> <path (e.g. /)>\n", argv[0]);
    return 0;
  }

  char* tlsHost = argv[1];
  char* tlsPort = argv[2];
  char* reqPath = argv[3];

  /* Initialize wolfSSL */
  wolfSSL_Init();

  /* Create a socket that uses an internet IPv4 address,
   * Sets the socket to be stream based (TCP),
   * 0 means choose the default protocol. */
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create the socket\n");
    ret = -1;
    goto exit;
  }

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLS_client_method())) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    ret = -1;
    goto exit;
  }

  /* Load client certificates into WOLFSSL_CTX */
  if ((ret = wolfSSL_CTX_load_verify_buffer(
           ctx, rootCert, sizeof(rootCert) - 1 /* omit terminal null */,
           WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load cert, please check the buffer.\n");
    goto exit;
  }

  /* Register callbacks */
  wolfSSL_SetIORecv(ctx, my_IORecv);
  wolfSSL_SetIOSend(ctx, my_IOSend);

  /* Initialize the server address struct with zeros */
  memset(&servAddr, 0, sizeof(servAddr));

  /* NEW: look up name */
  struct hostent* hostnm = gethostbyname(tlsHost);
  if (hostnm == NULL) {
    puts("ERROR: gethostbyname() failed");
    goto exit;
  }

  /* Fill in the server address */
  servAddr.sin_family = AF_INET; /* using IPv4 */
  servAddr.sin_port = htons(atoi(tlsPort));
  servAddr.sin_addr.s_addr = *((unsigned long*)hostnm->h_addr);

  /* Open TCP connection to the server */
  if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
    fprintf(stderr, "ERROR: failed to connect\n");
    ret = -1;
    goto exit;
  }

  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
    ret = -1;
    goto exit;
  }

  /* NEW: enable SNI */
  if ((ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, tlsHost,
                            strlen(tlsHost))) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to set host for SNI\n");
    goto exit;
  }

  /* Attach wolfSSL to the socket */
  wolfSSL_set_fd(ssl, sockfd);

  /* Turn on domain name check */
  if ((ret = wolfSSL_check_domain_name(ssl, tlsHost)) != WOLFSSL_SUCCESS) {
    puts("Failed to enable domain name check");
    goto exit;
  };

  /* TLS handshake with server */
  if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
    int err = wolfSSL_get_error(ssl, ret);
    fprintf(stderr, "ERROR: failed to connect to wolfSSL, error %i\n", err);
    goto exit;
  }

  char getReqBuff[1024];
  snprintf(getReqBuff, sizeof(getReqBuff),
           "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", reqPath, tlsHost);
  len = strlen(getReqBuff);

  /* Send the message to the server */
  if ((ret = wolfSSL_write(ssl, getReqBuff, len)) != len) {
    fprintf(stderr, "ERROR: failed to write\n");
    goto exit;
  }

  do {
    ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1 /* leave space for null-termination when printed as string */);
    if (ret == -1) {
      fprintf(stderr, "ERROR: failed to read\n");
      goto exit;
    }
    if (ret > 0) {
      buff[ret] = 0;  // null-terminate the string
      printf("data: %s\n", buff);
    }

  } while (ret > 0);

  ret = 0;

exit:
  /* Cleanup and return */
  if (ssl) wolfSSL_free(ssl); /* Free the wolfSSL object              */
  if (sockfd != SOCKET_INVALID)
    close(sockfd);                /* Close the connection to the server   */
  if (ctx) wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  wolfSSL_Cleanup();              /* Cleanup the wolfSSL environment          */

  return ret; /* Return reporting a success               */
}
