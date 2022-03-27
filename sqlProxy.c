#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/poll.h>
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
#define HEADSIZE 4
#define MAXDATASIZE 200000
#define INF_DELAY -1
#define ANY_PID -1

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
        return -1;
    }
    
    for(servinfo; servinfo != NULL; servinfo = servinfo->ai_next){
        sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
        if(sock_fd == -1){
            perror("server: socket");
            continue;
        }
        // if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1){
        //     perror("server: setsockopt error \n");
        //     continue;
        // }
        if(direction == IN)
        {
            if(bind(sock_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
                close(sock_fd);
                perror("server: bind");
                continue;
            }

            
        }else if(direction == OUT){
            if(connect(sock_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
                close(sock_fd);
                perror("connection error");
                continue;
            }
        }

        break;
    }
    if(direction == IN){
        if(servinfo == NULL){
            fprintf(stderr, "server: failed to bind\n");
            return -1;
        }
    }else if(direction == OUT){
        if(servinfo == NULL){
            fprintf(stderr, "server: failed to connect\n");
            return -1; 
        }
    }
    

    freeaddrinfo(servinfo);
    return sock_fd;
}

int NewReSend(int sock_in_fd, int sock_out_fd, char *d_buf){
    int recv_size = 1;
    u_char header[HEADSIZE];
    memset(header, 0, 4);
    recv_size = recv(sock_in_fd, header, HEADSIZE, 0);
    if(recv_size == -1){
        close(sock_in_fd);
        perror("recv header");
        return -1;
    }else if(recv_size == 0){
        return 0;
    }

    uint32_t pack_size;
    pack_size = ((uint32_t)header[0] | (uint32_t)header[1] << 8 | (uint32_t)header[2] << 16);
    
    d_buf = malloc(pack_size + HEADSIZE);
    memset(d_buf, 0, (pack_size + HEADSIZE));
    memcpy(d_buf, header, HEADSIZE);
    char *s_buf = NULL;
    s_buf = d_buf + HEADSIZE;

    recv_size = recv(sock_in_fd, s_buf, pack_size, 0);
    if(recv_size == -1){
        close(sock_in_fd);
        perror("recv");
        exit(1);
    }


    if(send(sock_out_fd, d_buf, pack_size + HEADSIZE, 0) == -1)
    {
        perror("send");
        close(sock_out_fd);
        exit(1);
    }
    // for (int i = 1; i < pack_size; i++){
    // printf("%c", s_buf[i]);
    // }
    // printf("\n");
    free(d_buf);
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
    struct sockaddr_storage their_addr;
    char *d_buf = NULL;
    pid_t pid;
    
    sock_in_fd = BindPort(PORT_IN, IN);    
    if(sock_in_fd == -1){
        fprintf(stderr, "Server shutting down \n");
        exit(1);
    }
    
    if(listen(sock_in_fd, BACKLOG) == -1){
        perror("server: listen \n");
        fprintf(stderr, "Server shutting down \n");
        exit(1);
    }
    while(1){
        struct pollfd sock_fds;
        struct pollfd *psock_fds = &sock_fds;
        int num_fds = 0;
        sock_fds.fd =  sock_in_fd;
        sock_fds.events = POLLIN;
        sock_fds.revents = 0;
        num_fds = 1;

        if(poll(psock_fds, num_fds, INF_DELAY) < 0){
            perror("poll() failed");
            exit(1);
        }
        if(sock_fds.revents == POLLIN){
            pid = fork();
        }

        if(pid == -1){
            perror("fork \n");
            exit(1);
        }else if(pid > 0){
            waitpid(ANY_PID, NULL, WNOHANG);
            continue;
        }else{
            while(1){
                socklen_t sin_size = sizeof their_addr;
                client_fd = accept(sock_in_fd, (struct sockaddr *)&their_addr, &sin_size);
                if(client_fd == -1){
                    close(client_fd);
                    perror("accept \n");
                    continue;        
                }

                // char s[INET6_ADDRSTRLEN];
                // inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
                // printf("connected from %s \n", s);       

                server_fd = BindPort(PORT_OUT, OUT);
                if(server_fd == -1){
                    fprintf(stderr, "Could not connect to MySQL server \nServer shutting down \n");
                    exit(1);
                }

                int data_size = 0;
                do{
                    struct pollfd fds[2];
                    memset(fds, 0, sizeof(fds));
                    fds[0].fd =  server_fd;
                    fds[0].events = POLLIN;
                    fds[0].revents = 0;
                    fds[1].fd =  client_fd;
                    fds[1].events = POLLIN;
                    fds[1].revents = 0;
                    num_fds = 2;
                    
                    if(poll(fds, num_fds, INF_DELAY) < 0){
                        perror("poll() failed");
                        exit(1);
                    }
                    if(fds[0].revents == POLLIN){
                        data_size = NewReSend(server_fd, client_fd, d_buf);
                        //printf("\n server - client resend \n data_size = %d \n ------------------ \n", data_size);
                    } else if(fds[1].revents == POLLIN){
                        data_size = NewReSend(client_fd, server_fd, d_buf); 
                        //printf("\n client - server resend \n data_size = %d \n ------------------ \n", data_size);
                    } else {
                        continue;
                    }
                }while(data_size != 0);
                close(server_fd);
                close(client_fd);
                printf("child process exit\n");
                exit(0);
            }
        }
    }
    close(sock_in_fd);
    return 0;
}
