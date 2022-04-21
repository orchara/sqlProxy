#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>

#define P_LENGTH_SIZE 3
#define SEQ_ID_SIZE 1
#define SENDER_LENGTH 1
#define COM_QUERY 0x03
#define PACKET_HEADER 5
#define HANDSHAKEV10 0x0a
#define NAME_OFFSET 32
#define MAX_LENGTH_AP_DATA 21
#define LENGTH_AP_DATA_1 8
#define HS_RESERVED 10


//Capability Flags
#define CLIENT_PLUGIN_AUTH 0x00080000
#define CLIENT_SECURE_CONNECTION 0x00008000


struct command ComQueryRead();
void ReadPacket();
ssize_t Read(int fd, void *buf, size_t size_buf_element, size_t count);

struct sql_packet
{
    __uint8_t sender;
    __uint32_t playload_length;
    __uint8_t sequence_id;
    u_char *playload;

};

#pragma pack(push, 1)
typedef struct sql_packet_bit
{
    __uint8_t sender;                   
    __uint32_t playload_length : 24;     
    __uint8_t sequence_id;              
    u_char pad[3];  //TODO задать расчет заполнителя через sizeof/offsetof
    u_char *playload;

}sql_packet_bit;
#pragma pack(pop)

struct command
{
    __uint8_t name;
    void *playload;
};

struct command ComQueryRead(){

}

void ReadPacket(int in_fd, sql_packet_bit *pack){
    u_char header[PACKET_HEADER];
    Read(in_fd, header, sizeof(u_char), PACKET_HEADER);
    memcpy(pack, header, PACKET_HEADER);
    pack->playload = (u_char *)malloc(pack->playload_length);
    if(pack->playload == NULL){
        perror("malloc in ReadPacket() error");
        exit(1);
    }
    memset(pack->playload, 0, pack->playload_length);
    Read(in_fd, pack->playload, sizeof(u_char), pack->playload_length);
}


/*Wrapper function for read()
*reads from FD until COUNT bytes are read 
*SIZE_BUF_ELEMENT is size of buf variable type
*/
ssize_t Read(int fd, void *buf, size_t size_buf_element, size_t count){
    ssize_t read_size = 0, unread = count - read_size;
    while(unread > 0){
        unread = unread - read_size;
        buf = buf + (size_buf_element * read_size);
        read_size = read(fd, buf, unread);
        if(read_size < 0){
            perror("read");
            exit(1); //TODO заменить exit чем-то более полезным
        }
    }
}

/*Wrapper for VOID MALLOC(size_t __size)
*with NULL pointer check, error exit
 and ZERO memset*/
void *Malloc(size_t size){
    void *ptr = malloc(size);
    if (ptr == NULL){
        perror("malloc error");
        exit(1);
    }else{
        memset(ptr, 0, size);
        return ptr;
    }
}

/*Count and return length of string[NUL]
*from body of sql packet
**STRING - is pointer to playload buf
* OFFSET - offset to the first character of the string
*/
int NullStringLength(u_char *string, u_int32_t offset){
    u_int32_t stringsize = 1; //include null terminator
    int i = offset;
    while(string[i] != 0x00){     
        i++;   
        stringsize++;
    }
    return stringsize;
}

int main(void)
{   
    //printf("%ld\n", sizeof(sql_packet_bit));
    //printf("%ld\n", sizeof(struct command));

    mode_t mode;
    int flags, fd;
    flags = O_RDONLY;
    mode = S_IRWXU | S_IRWXG | S_IROTH; // доcтуп 774
    fd = open("./logs/test", flags, mode);
    if(fd < 0){
        perror("open log file");
        return -1;
    }



    //отделить фазу подключения от фазы команд
        //server greeteng - server
        //login request - client
        //auth switch request - server
        //auth switch response - client
        //response OK / err_pack
    //в лог выводим имя пользователя и время коннекта
    ///login sequence
    sql_packet_bit pack;
    #pragma pack(push, 1)
    typedef struct hand_shake_v10               //Server greeting(Handshake pack)
    {
        u_int8_t protocol_version;
                                        //u_char *server_version;
        u_int32_t connection_id;
        u_char auth_plugin_data_p1[LENGTH_AP_DATA_1+sizeof(char)];
        u_int16_t capability_flags_1;
        //if more data in the packet:
        u_int8_t character_set;
        u_int16_t status_flags;
        u_int16_t capability_flags_2;
        //if capabilities & CLIENT_PLUGIN_AUTH
        u_int8_t length_auth_p_data; //else filler == 0x00
        u_char reserved[HS_RESERVED];
        //if capabilities & CLIENT_SECURE_CONNECTION
        u_char auth_plugin_data_p2[MAX_LENGTH_AP_DATA-LENGTH_AP_DATA_1]; //max length is 13
        u_char *server_version;
        //if capabilities & CLIENT_PLUGIN_AUTH
        u_char *auth_plugin_name;
    }h_s_v10;
    #pragma pack(pop)
    h_s_v10 hs_pack;
    u_int32_t read_offset = 0, read_size = 0;
    memset(&hs_pack,0,sizeof(hs_pack));
    ReadPacket(fd, &pack);  
    char *p_hs_pack = (char *)&hs_pack;        
    p_hs_pack[offsetof(h_s_v10, protocol_version)] = pack.playload[read_offset];                //protocol version
    read_offset += sizeof(hs_pack.protocol_version);
    if(hs_pack.protocol_version == HANDSHAKEV10){   // handler for handshake protocol v 10
        read_size = NullStringLength(pack.playload, read_offset);
        hs_pack.server_version = Malloc(read_size); 
        memcpy(hs_pack.server_version, (pack.playload + read_offset), read_size);
        u_int32_t req_field_length = sizeof(hs_pack.protocol_version) + 
                                     read_size +       //length of server version
                                     sizeof(hs_pack.connection_id) + 
                                     sizeof(hs_pack.auth_plugin_data_p1);
        if(pack.playload_length > req_field_length)
        {
            read_offset += read_size;
            read_size = sizeof(hs_pack.connection_id) + 
                        sizeof(hs_pack.auth_plugin_data_p1) + 
                        sizeof(hs_pack.capability_flags_1) +
                        sizeof(hs_pack.character_set) +
                        sizeof(hs_pack.status_flags) +
                        sizeof(hs_pack.capability_flags_2);
            memcpy((p_hs_pack + offsetof(h_s_v10, connection_id)), 
                   (pack.playload + read_offset),
                    read_size);
            read_offset += read_size;
            u_int32_t capabilities;
            memcpy((char *)&capabilities, 
                    p_hs_pack + offsetof(h_s_v10,capability_flags_1), 
                    sizeof(hs_pack.capability_flags_1));
            memcpy(((char *)&capabilities) + sizeof(hs_pack.capability_flags_1), 
                    p_hs_pack + offsetof(h_s_v10,capability_flags_2), 
                    sizeof(hs_pack.capability_flags_2)); 
            //capabilities check
            if(capabilities & CLIENT_PLUGIN_AUTH){
                printf("cli plug yes\n");
            }

        }else{
            read_offset += read_size;
            read_size = sizeof(hs_pack.connection_id) + 
                        sizeof(hs_pack.auth_plugin_data_p1);
            memcpy((p_hs_pack + offsetof(h_s_v10, connection_id)), 
                   (pack.playload + read_offset),
                    read_size);            
        }
        
        
    }else{                                          // handler for handshake protocol v 9
        printf("protocol version is %d\n this version of protocol not supported\n", hs_pack.protocol_version);
    }


    free(pack.playload);
    ReadPacket(fd,&pack);           //Login request(Handshake response)
    struct hs_response_41
    {
        u_int32_t capability_flags;
        u_int32_t max_packet_size;
        u_int8_t character_set;
        u_char reserved[23];
        u_char *username;
    } hs_res;
   
    memcpy(&hs_res.capability_flags, pack.playload, sizeof(u_int32_t));    
    u_int32_t namelength = NullStringLength(pack.playload, NAME_OFFSET);
    hs_res.username = (u_char *)malloc(namelength);
    if(hs_res.username == NULL){
        perror("malloc hs_res.username error");
        exit(1);
    }
    memcpy(hs_res.username, (pack.playload+NAME_OFFSET), namelength);
    printf("\n-------------\nusrer name: %s\n", hs_res.username);
    free(pack.playload);


    free(hs_pack.server_version); //TODO find place to this

    // printf("read result - %d \nstring is %s\n", pack.playload_length, pack.playload);
    // free(pack.playload);    
    


    //фаза команд
        //принять пакет в буфер
        //определить отправителя
        //определить длину, очередь и тело пакета, сохранить в структуру
            //клиент:
                //в зависимости от командного бита пихаем тело команды в нужную переменную
                //пишем команду и время в лог
            //сервер:
                //???
                //

                exit(0);
}