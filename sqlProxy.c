#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>


#define PORT_IN "3305"
#define PORT_OUT "3306"
#define IN 0
#define OUT 1
#define BACKLOG 10
#define MAXDATASIZE 200000

void *get_in_addr(struct sockaddr *sa)
{
    if(sa->sa_family == AF_INET){
        return &(((struct sockaddr_in*)sa)->sin_addr);
    } else {
        return &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
}

int BindPort(const char *port, int direction){
    int status, sock_fd, yes = 1;
    struct addrinfo hints, *servinfo = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    status = getaddrinfo(NULL, port, &hints, &servinfo);
    if (status !=0){
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }

    for(servinfo; servinfo != NULL; servinfo = servinfo->ai_next){
        sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
        if(sock_fd == -1){
            perror("server: socket \n");
            continue;
        }
        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1){
            perror("server: setsockopt error \n");
            continue;
        }
        if(direction == IN)
        {
            if(bind(sock_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
                close(sock_fd);
                perror("server: bind \n");
                continue;
            }
        }else if(direction == OUT){
            if(connect(sock_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
                close(sock_fd);
                perror("connection error");
            }
        }

        break;
    }
    if(direction == IN){
        if(servinfo == NULL){
            fprintf(stderr, "server: failed to bind\n");
            exit(1);
        }
    }else if(direction == OUT){
        if(servinfo == NULL){
            fprintf(stderr, "server: failed to connect\n");
            exit(1); 
        }
    }
    

    freeaddrinfo(servinfo);
    return sock_fd;
}

int ReSend(int sock_in_fd, int sock_out_fd, char *buf){
    int recv_size;
    recv_size = recv(sock_in_fd, buf, MAXDATASIZE-1, 0);
    if(recv_size == -1){
        close(sock_in_fd);
        perror("recv");
        exit(1);
    }

    if(send(sock_out_fd, buf, recv_size, 0) == -1)
    {
        perror("send");
        close(sock_out_fd);
        exit(1);
    }
    return recv_size;
}

void DebugPrint(char *buf, int data_size){
    for (int i =0; i < data_size; i++){
    printf("%c", buf[i]);
    }
    printf("\n");
}

int main ()
{
    int sock_in_fd, server_fd, client_fd;
    sock_in_fd = BindPort(PORT_IN, IN);
    

    if(listen(sock_in_fd, BACKLOG) == -1){
        perror("server: listen \n");
        exit(1);
    }

    struct sockaddr_storage their_addr;
    char buf[MAXDATASIZE];
    memset(buf, 0, sizeof buf);
    socklen_t sin_size = sizeof their_addr;
    client_fd = accept(sock_in_fd, (struct sockaddr *)&their_addr, &sin_size);
    if(client_fd == -1){
        close(client_fd);
        perror("accept");
        exit(1);        
    }

    char s[INET6_ADDRSTRLEN];
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
    printf("connected from %s \n", s);

    server_fd = BindPort(PORT_OUT, OUT);

    int data_size = 10;

    while (data_size != 0){

        memset(buf, 'A', sizeof buf);
        data_size = ReSend(server_fd, client_fd, buf);
        
        DebugPrint(buf, data_size);

        memset(buf, 'B', sizeof buf);
        data_size = ReSend(client_fd, server_fd, buf);

        DebugPrint(buf, data_size);
    }

    close(sock_in_fd);
    close(server_fd);
    close(client_fd);
    return 0;
}
