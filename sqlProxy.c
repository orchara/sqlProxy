#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>


#define PORT_IN "3305"
#define PORT_OUT "3306"
#define IN 0
#define OUT 1
#define BACKLOG 10
#define HEADSIZE 4
#define INF_DELAY -1
#define DELAY 0
#define ANY_PID -1
#define FALSE 0
#define TRUE 1
#define HEAD_OFFSET 5
#define SERVER 0
#define CLIENT 1

volatile sig_atomic_t chld_flag = FALSE, quit_flag = FALSE;
void DebugPrint(char *buf, int data_size);
void *GetInAddr(struct sockaddr *sa);
int BindPort(const char *port, int direction);
int32_t ReSend(int sock_in_fd, int sock_out_fd, char **d_buf);
int OpenLogFile(void);
void LogWrite(int log_fd, char *buf, int32_t data_size, int8_t sender);

void SigchldHandler(int sig){
    chld_flag = TRUE;
}

void QuitHhandler(int sig){
    quit_flag = TRUE;
}

void *GetInAddr(struct sockaddr *sa)
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

int32_t ReSend(int sock_in_fd, int sock_out_fd, char **d_buf){  //TODO add a resending size control
    int32_t recv_size = 0;
    u_char header[HEADSIZE];
    uint32_t pack_size;
    memset(header, 0, 4);
    recv_size = recv(sock_in_fd, header, HEADSIZE, 0);
    if(recv_size == -1){
        perror("recv header");
        return -1;
    }

    
    pack_size = ((uint32_t)header[0] | (uint32_t)header[1] << 8 | (uint32_t)header[2] << 16);
    
    *d_buf = malloc(pack_size + HEADSIZE);
    memset(*d_buf, 0, (pack_size + HEADSIZE));
    memcpy(*d_buf, header, HEADSIZE);
    char *s_buf = NULL;
    s_buf = *d_buf + HEADSIZE;

    recv_size = recv(sock_in_fd, s_buf, pack_size, 0);
    if(recv_size == -1){        
        perror("recv");
        return -1;
    }


    if(send(sock_out_fd, *d_buf, pack_size + HEADSIZE, 0) == -1)
    {
        perror("send");       
        return -1;
    }
    if((pack_size == 1) && ((*d_buf)[4] == 0x01) && (*d_buf)[3] == 0x00){ //command quit        
        return 0;
    }
    return pack_size + HEADSIZE;
}

void DebugPrint(char *buf, int data_size){
    for (int i =0; i < data_size; i++){
    printf("%c", buf[i]);
    }
    printf("\n");
}

int OpenLogFile(void){
    mode_t mode;
    int flags, fd;
    flags = O_CREAT | O_EXCL | O_WRONLY;
    mode = S_IRWXU | S_IRWXG | S_IROTH; // доcтуп 774
    long int s_time;
    struct tm *m_time;
    s_time = time(NULL);
    m_time = localtime(&s_time);
    //const char path[] = "./logs/log_%y-%m-%d_%H-%M-%S.txt";
    const char path[] = "./logs/test1";
    char pathname[(strlen(path)+1)];
    strftime(pathname, (strlen(path)+1), path, m_time);

    if(mkdir("./logs", mode) < 0 && (errno != EEXIST)){
        perror("OpenLogFile - mkdir()");
        exit(1);       
    }
    fd = open(pathname, flags, mode);
    if(fd < 0){
        perror("OpenLogFile - open()");
        fprintf(stderr, "Can't create log file \n");
        exit(1); 
    }
    return fd;
}

void LogWrite(int log_fd, char *buf, int32_t data_size, int8_t sender){    
    int32_t wr_size = 0;
    if(lockf(log_fd, F_LOCK, data_size) < 0){
        perror("block error");
        exit(1);
    }
    write(log_fd, &sender, 1);
    while(data_size > 0){
        data_size = data_size - wr_size;
        buf = buf + wr_size;        
        wr_size = write(log_fd, buf, data_size);
        if(wr_size < 0){
            perror("write to log file error");
            exit(1);                                
        }
    }
    lockf(log_fd, F_ULOCK, 0);
}

/*checking the quit flag*/
int QuitCheck(sigset_t* set){
    int result = FALSE;
    if(pthread_sigmask(SIG_UNBLOCK, set, NULL) == -1){
        perror("pthread_sigmask");
        exit(1);
    }  
    if(quit_flag){
        result = TRUE;
    }
    if(pthread_sigmask(SIG_BLOCK, set, NULL) == -1){
        perror("pthread_sigmask");
        exit(1);
    }
    return result;
}

/*Wrapper for PTHREAD_SIGMASK
Modify the signal mask for the calling thread. The arguments have
the same meaning as for sigprocmask(2).*/
int Pthread_sigmask(int __how, const sigset_t * __restrict__ __newmask, sigset_t * __restrict__ __oldmask){
    if(pthread_sigmask(__how, __newmask, __oldmask) == -1){
        perror("pthread_sigmask");
        exit(1);
    }
}

/*setup handlers for signals*/
void SigSetup(sigset_t* set){
    struct sigaction child_sa, quit_sa;    
    memset(&quit_sa, 0, sizeof(quit_sa));
    sigemptyset(set);
    sigaddset(set, SIGCHLD);
    sigaddset(set, SIGINT);
    child_sa.sa_handler = SigchldHandler;
    child_sa.sa_mask = *set;
    quit_sa.sa_handler = QuitHhandler;
    quit_sa.sa_mask = *set;
    

    if(sigaction(SIGINT, &quit_sa, NULL) == -1){
        perror("sigaction quit");
        exit(1);
    }
    if(sigaction(SIGCHLD, &child_sa, NULL) == -1){
        perror("sigaction chld");
        exit(1);
    }
}

int main (void)
{
 
    int sock_in_fd, log_fd;
    pid_t m_pid = getpid();
    sigset_t set;
    SigSetup(&set);   
    Pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    sock_in_fd = BindPort(PORT_IN, IN);  
    //printf("sock in fd is %d\n", sock_in_fd); 
    if(sock_in_fd == -1){
        fprintf(stderr, "Server shutting down \n");
        exit(1);
    }
    
    if(listen(sock_in_fd, BACKLOG) == -1){
        perror("server: listen \n");
        fprintf(stderr, "Server shutting down \n");
        exit(1);
    }

    log_fd = OpenLogFile();

    while(!QuitCheck(&set)){        //main awayting connection loop
        
        struct pollfd sock_fds;
        int poll_ret = 0, num_fds = 0;  
        sock_fds.fd =  sock_in_fd;
        sock_fds.events = POLLIN;
        sock_fds.revents = 0;

        num_fds = 1;
        int server_fd, client_fd;
        struct sockaddr_storage their_addr;
        socklen_t sin_size = sizeof(their_addr);

        poll_ret = poll(&sock_fds, num_fds, DELAY);
        if(poll_ret < 0){
            perror("poll() failed");
            exit(1);
        }
        if((poll_ret > 0) && (sock_fds.revents & POLLIN)){ //connection in queue
            client_fd = accept(sock_in_fd, (struct sockaddr *)&their_addr, &sin_size);
            if(client_fd == -1){
                close(client_fd);
                close(sock_in_fd);
                close(log_fd);
                perror("accept \n");
                exit(1);        
            }
            //printf("client fd is %d\n", client_fd);
        
            server_fd = BindPort(PORT_OUT, OUT);
            if(server_fd == -1){
                close(server_fd);
                close(client_fd);
                close(sock_in_fd);
                close(log_fd);
                fprintf(stderr, "Could not connect to MySQL server \nServer shutting down \n");
                exit(1);
            }
            //printf("server fd is %d\n", server_fd);              
            
            pid_t pid = 1;
            pid = fork();
            if(pid < 0){
                perror("fork");
                close(server_fd);
                close(client_fd);
                close(sock_in_fd);
                close(log_fd);
                exit(1);
            }else if(pid == 0){          //child process  
                int32_t data_size = 0;
                int poll_chk;
                char *d_buf = NULL;
                struct pollfd fds[2];
                close(sock_in_fd); 
                do{
                    if(QuitCheck(&set)){
                        break;
                    }
                    memset(fds, 0, sizeof(fds));                    
                    fds[0].fd =  server_fd;
                    fds[0].events = POLLIN;
                    fds[1].fd =  client_fd;
                    fds[1].events = POLLIN;                    
                    num_fds = 2;                    
                    fds[0].revents = 0;
                    fds[1].revents = 0; 
                    poll_chk = poll(fds, num_fds, DELAY);
                    if(poll_chk < 0){
                        perror("poll() failed");
                        exit(1);
                    }                    
                    if(fds[0].revents == POLLIN){                                
                        data_size = ReSend(server_fd, client_fd, &d_buf);
                        LogWrite(log_fd, d_buf, data_size, SERVER);
                        free(d_buf);
                    } else if(fds[1].revents == POLLIN){                                
                        data_size = ReSend(client_fd, server_fd, &d_buf); 
                        LogWrite(log_fd, d_buf, data_size, CLIENT);
                        free(d_buf);
                    }
                }while(data_size > 0);
                
                close(client_fd);
                close(server_fd);
                exit(0);
                
            }else if(pid >0){
                close(client_fd);
                close(server_fd);
            }
        }
        if(getpid() == m_pid){       //parent process
            if(chld_flag & TRUE){
                while(waitpid(ANY_PID, NULL, WNOHANG) > 0);
                chld_flag = FALSE; 
            } 
        } 
    }
    // quit sequence
    pid_t chld = 0;
    do{
        chld = waitpid(ANY_PID, NULL, 0);
        if(chld == -1 && errno & ECHILD){
           break; 
        }
        if(chld == -1){
            perror("on close waitpid");
        }
    }while(chld > 0);
    close(sock_in_fd);
    close(log_fd);
    printf("socket in fd is closed\n");
    return 0;
}
