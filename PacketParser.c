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
#define RES_RESERVED 23
#define PACK_RESERVED_OFFSET 5
#define HSR320_RESERVED_OFFSET 5
#define MAX_PACKET_SIZE_LENGTH 3


//Capability Flags
#define CLIENT_PLUGIN_AUTH 0x00080000
#define CLIENT_SECURE_CONNECTION 0x00008000
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0X00200000
#define CLIENT_CONNECT_WITH_DB 0X00000008
#define CLIENT_CONNECT_ATTRS 0x00100000
#define CLIENT_PROTOCOL_41 0x00000200
#define CLIENT_SSL 0x00000800


#pragma pack(push, 1)
typedef struct sql_packet_bit
{
    __uint8_t sender;                   
    __uint32_t playload_length : 24;     
    __uint8_t sequence_id;              
    u_char reserved[sizeof(u_char*) - (PACK_RESERVED_OFFSET % sizeof(u_char*))];
    u_char *playload;

}sql_packet_bit;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct hand_shake       //Server greeting(Handshake pack v10)
{
    u_int8_t protocol_version;
                                    //u_char *server_version;
    u_int32_t connection_id;
    u_char auth_plugin_data_p1[LENGTH_AP_DATA_1];
    u_char filler;
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
    u_char *auth_plugin_data_full; //in protocol version 9
}hand_shake;
#pragma pack(pop)

typedef struct client_conn_attrs{
    u_char *key;
    u_char *value;
    struct client_conn_attrs *next;
}client_conn_attrs;

#pragma pack(push, 1)
typedef struct hs_response_41           //login request (handshake response v41)
{
    u_int32_t capability_flags;
    u_int32_t max_packet_size;
    u_int8_t character_set;
    u_char reserved[RES_RESERVED];
    u_char *username;
    /*if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA {lenenc len_auth_response}
    ELSE if capabilities & CLIENT_SECURE_CONNECTION {1b len_auth_responce}
    ELSE len_auth_response = 0*/
    u_int64_t len_auth_response; 
    u_char *auth_response;
    //if capabilities & CLIENT_CONNECT_WITH_DB
    u_char *database;
    //if capabilities & CLIENT_PLUGIN_AUTH
    u_char *auth_plugin_name;
    //if capabilities & CLIENT_PLUGIN_ATTRS
    u_int64_t len_key_values;
    client_conn_attrs *conn_attrs;

} hs_response_41;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct hs_response_320{
    u_int16_t capability_flags;
    u_int32_t max_packet_size : 24;
    u_char reserved[sizeof(u_char*) - (HSR320_RESERVED_OFFSET % sizeof(u_char*))];
    u_char *username;
    u_char *auth_response;
    u_char *database;
}hs_response_320;
#pragma pack(pop)

typedef struct auth_switch_rq 
{   
    u_int8_t status;
    u_char *plugin_name;
    u_char *auth_plugin_data;
}auth_switch_rq;

struct command
{
    __uint8_t name;
    void *playload;
};




void ReadPacket(int in_fd, sql_packet_bit *pack);
ssize_t Read(int fd, void *buf, size_t size_buf_element, size_t count);
int GetLenEncInt(u_char *buf, int64_t *result);
u_int64_t ReadLenIncStr(u_char *buf, u_char **str);
void *Malloc(size_t size);
void ConnAttrsFree(client_conn_attrs *pack);
void AuthSwitchRqFree(auth_switch_rq *pack);

struct command ComQueryRead(){

}

/*read and copy length encoded string from BUF to STR
*return num of bytes readed from BUF
*/
u_int64_t ReadLenIncStr(u_char *buf, u_char **str){
    u_int64_t length = 0;
    u_int64_t offset = 0;
    offset = GetLenEncInt(buf, &length);
    if(offset < 0){
        fprintf(stderr, "GetLenIncStr error: can't define str length\n");
        return 0;
    }else{        
        u_char eos = '\0';
        *str = Malloc(length + sizeof(char));
        memcpy(*str, buf+offset, length);
        memcpy(*str + length, &eos, sizeof(u_char));
        return offset+length;
    }
}

/*read and copy length encoded integer from BUF to RESULT
*return num of bytes, readed from BUF,
or -1 if first byte of BUF not in range (0x00 < x < 0xfe)
*/
int GetLenEncInt(u_char *buf, int64_t *result){
    int offset = 0;
    *result = 0;
    if(buf[0] < 0xfb){
        *result = buf[0];
        offset = 1;
    }else if(buf[0] == 0xfc){
        offset = 2;
        memcpy(result, buf+1, offset);
    }else if(buf[0] == 0xfd){
        offset = 3;
        memcpy(result, buf+1, offset);
    }else if(buf[0] == 0xfe){
        offset = 8;
        memcpy(result, buf+1, offset);
    }else{
        fprintf(stderr, "buffer is not contain a length encoded integer\nbuf[0] = %d\n", buf[0]);
        offset = -1;
    }
    return offset;
}

/*Get data from IN_FD stream and save it to struct SQL_PACKET_BIT 
*playload of sql packet stored in mem alocated with malloc, 
*pointer stored in *SQL_PACKET_BIT::PLAYLOAD
*/
void ReadPacket(int in_fd, sql_packet_bit *pack){
    u_char header[PACKET_HEADER];
    Read(in_fd, header, sizeof(u_char), PACKET_HEADER);
    memcpy(pack, header, PACKET_HEADER);
    pack->playload = malloc(pack->playload_length);
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
**STRING - is pointer to first char of string 
*/
u_int32_t NullStringLength(u_char *string){
    u_int32_t stringsize = 0; 
    int i = 0;
    while(1){     
        if(string[i] != 0x00){
            i++;   
            stringsize++;
        }else{
            stringsize++;
            break;
        }
    }
    return stringsize;
}

/*copy  string[NULL] from BUF to STR
*BUF is a first char of string pointer 
return string length, include '\0'
*/
u_int32_t GetNullStr(u_char *buf, u_char **str){
    u_int32_t read_size = 0;
    read_size = NullStringLength(buf);
    *str = Malloc(read_size);
    memcpy(*str, buf, read_size);
    return read_size;
}

void HandshakeV10Free(hand_shake *pack){
    free(pack->server_version);
    free(pack->auth_plugin_name);
    return;
}

void HSResponseFree(hs_response_41 *pack){
    free(pack->username);
    free(pack->auth_response);
    free(pack->auth_plugin_name);
    free(pack->database);
    ConnAttrsFree(pack->conn_attrs);

}

void ConnAttrsFree(client_conn_attrs *pack){
    client_conn_attrs *this = pack, *next = NULL;
    while(this != NULL){
        free(this->key);
        free(this->value);
        next = this->next;
        free(this);
        this = next;       
    }    
}

void AuthSwitchRqFree(auth_switch_rq *pack){
    free(pack->auth_plugin_data);
    free(pack->plugin_name);
}

int main(void)
{   
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
            //or ssl request
            //or old login request (HS_RES 320)
        //auth switch request - server
            //or old auth switch request
        //auth switch response - client
        //response OK / err_pack
    
    ///login sequence
    sql_packet_bit pack;
    hand_shake hs_pack;
    char *p_hs_pack = (char *)&hs_pack;
    hs_response_320 hs_res_320;
    hs_response_320 *p_hs_res_320 = &hs_res_320;
    memset(&hs_res_320, 0, sizeof(hs_res_320));
    hs_response_41 hs_res;
    char *p_hs_res = (char *)&hs_res;
    memset(&hs_res, 0, sizeof(hs_res));

    u_int32_t server_capabilities;
    u_int64_t read_offset = 0, read_size = 0;
    
    memset(&pack, 0, sizeof(pack));
    memset(&hs_pack, 0, sizeof(hs_pack));
    ReadPacket(fd, &pack);          
    p_hs_pack[offsetof(hand_shake, protocol_version)] = pack.playload[read_offset];                //protocol version
    read_offset += sizeof(hs_pack.protocol_version);
    if(hs_pack.protocol_version == HANDSHAKEV10){   // handler for handshake protocol v 10
        read_size = GetNullStr(pack.playload + read_offset, &hs_pack.server_version);
        read_offset += read_size;
        u_int32_t req_field_length = sizeof(hs_pack.protocol_version) + 
                                     read_size +       //length of server version
                                     sizeof(hs_pack.connection_id) + 
                                     sizeof(hs_pack.auth_plugin_data_p1) + 
                                     sizeof(hs_pack.filler);
        if(pack.playload_length > req_field_length)
        {            
            read_size = sizeof(hs_pack.connection_id) + 
                        sizeof(hs_pack.auth_plugin_data_p1) + 
                        sizeof(hs_pack.filler) +
                        sizeof(hs_pack.capability_flags_1) +
                        sizeof(hs_pack.character_set) +
                        sizeof(hs_pack.status_flags) +
                        sizeof(hs_pack.capability_flags_2);
            memcpy((p_hs_pack + offsetof(hand_shake, connection_id)), 
                   (pack.playload + read_offset),
                    read_size);
            read_offset += read_size;            
            memcpy((char *)&server_capabilities, 
                    p_hs_pack + offsetof(hand_shake,capability_flags_1), 
                    sizeof(hs_pack.capability_flags_1));
            memcpy(((char *)&server_capabilities) + sizeof(hs_pack.capability_flags_1), 
                    p_hs_pack + offsetof(hand_shake,capability_flags_2), 
                    sizeof(hs_pack.capability_flags_2)); 
            if(server_capabilities & CLIENT_PLUGIN_AUTH){
                p_hs_pack[offsetof(hand_shake, length_auth_p_data)] = pack.playload[read_offset];
                read_offset += sizeof(hs_pack.length_auth_p_data);
            }            
            read_offset += sizeof(hs_pack.reserved);
            if(server_capabilities & CLIENT_SECURE_CONNECTION){
                read_size = hs_pack.length_auth_p_data - sizeof(hs_pack.auth_plugin_data_p1);
                memcpy(p_hs_pack + offsetof(hand_shake, auth_plugin_data_p2),
                       pack.playload + read_offset,
                       read_size);
                read_offset += read_size;
            }
            if(server_capabilities & CLIENT_PLUGIN_AUTH){
                read_size = pack.playload_length - read_offset;
                hs_pack.auth_plugin_name = Malloc(read_size);
                memcpy(hs_pack.auth_plugin_name,
                       pack.playload + read_offset,
                       read_size);
            }

        }else{
            read_size = sizeof(hs_pack.connection_id) + 
                        sizeof(hs_pack.auth_plugin_data_p1);
            memcpy((p_hs_pack + offsetof(hand_shake, connection_id)), 
                   (pack.playload + read_offset),
                    read_size);            
        }
        
        
    }else{                          // handler for handshake protocol v 9  
        read_size = GetNullStr(pack.playload + read_offset, &hs_pack.server_version);
        read_offset += read_size;
        read_size = sizeof(hs_pack.connection_id);
        memcpy((p_hs_pack + offsetof(hand_shake, connection_id)), 
                   (pack.playload + read_offset),
                    read_size);
        read_offset += read_size;
        GetNullStr(pack.playload + read_offset, &hs_pack.auth_plugin_data_full);
    }



    free(pack.playload);
    memset(&pack, 0, sizeof(pack));    
    ReadPacket(fd,&pack);    
    int16_t protocol_check = 0;
    memcpy(&protocol_check, pack.playload, sizeof(protocol_check));
    if(protocol_check & CLIENT_PROTOCOL_41){    //Login request(Handshake response v41)        

        read_offset = 0;
        read_size = sizeof(hs_res.capability_flags) +
                    sizeof(hs_res.max_packet_size) +
                    sizeof(hs_res.character_set);
        memcpy(p_hs_res + offsetof(hs_response_41, capability_flags), 
                pack.playload + read_offset,
                read_size);
        if(hs_res.capability_flags & CLIENT_SSL){   
            printf("logging with SSL connection not supported\n Please turn of SSL and restart proxy\n");
            exit(0);
        }
        read_offset += read_size;
        read_offset += sizeof(hs_res.reserved);   
        read_size = GetNullStr((pack.playload + read_offset), &hs_res.username);
        read_offset += read_size;
        if(hs_res.capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA){
            int offset = GetLenEncInt(pack.playload + read_offset, &hs_res.len_auth_response);
            if(offset < 0){
                char err[] = "Can't define length of auth response\n";
                hs_res.auth_response = Malloc(sizeof(err));
                strcpy(hs_res.auth_response, err);
            }else{
                read_offset += offset;
                hs_res.auth_response = Malloc(hs_res.len_auth_response);
                memcpy(hs_res.auth_response, (pack.playload + read_offset), hs_res.len_auth_response);
                read_offset += hs_res.len_auth_response;
            }
        }else if(hs_res.capability_flags & CLIENT_SECURE_CONNECTION){
            hs_res.len_auth_response = pack.playload[read_offset];
            read_offset += sizeof(char);
            hs_res.auth_response = Malloc(hs_res.len_auth_response);
            memcpy(hs_res.auth_response, (pack.playload + read_offset), hs_res.len_auth_response);
            read_offset += hs_res.len_auth_response;
        }else{
            read_size = GetNullStr(pack.playload +read_offset, &hs_res.auth_response);
            read_offset += read_size;
        }
        if(hs_res.capability_flags & CLIENT_CONNECT_WITH_DB){       
            read_size = GetNullStr(pack.playload +read_offset, &hs_res.database);
            read_offset += read_size;
        }
        if(hs_res.capability_flags & CLIENT_PLUGIN_AUTH){        
            read_size = GetNullStr(pack.playload +read_offset, &hs_res.auth_plugin_name);
            read_offset += read_size;
        }
        if(hs_res.capability_flags & CLIENT_CONNECT_ATTRS){
            int offset = GetLenEncInt((pack.playload + read_offset), &hs_res.len_key_values);
            if(offset < 0){
                fprintf(stderr, "Can't read lenght of all key-values\n");
            }else{
                read_offset += offset;
                for (client_conn_attrs **head = &hs_res.conn_attrs;                         //Read conn atrs pairs from stream
                    read_offset < pack.playload_length;        //while data in stream
                    head = &((*head)->next)){

                    *head = Malloc(sizeof(client_conn_attrs));
                    (*head)->next = NULL;
                    offset = ReadLenIncStr((pack.playload + read_offset), &((*head)->key));
                    if(offset < 0){
                        fprintf(stderr, "Can't read key-values\n");
                    }else{
                        read_offset += offset;
                    }
                    offset = ReadLenIncStr((pack.playload + read_offset), &((*head)->value));
                    if(offset < 0){
                        fprintf(stderr, "Can't read key-values\n");
                    }else{
                        read_offset += offset;
                    }                
                }
            }
        }
    }else{ //handler for HandshakeResponse320
        read_offset = 0;
        read_size = sizeof(hs_res_320.capability_flags) +
                    MAX_PACKET_SIZE_LENGTH;
        memcpy(p_hs_res_320, pack.playload, read_size);
        read_offset += read_size;
        read_offset += GetNullStr(pack.playload, &hs_res_320.username);
        if(hs_res_320.capability_flags & CLIENT_CONNECT_WITH_DB){

            read_offset += GetNullStr(pack.playload, &hs_res_320.auth_response);
            read_offset += GetNullStr(pack.playload, &hs_res_320.database);
        }else{
            read_size = pack.playload_length - read_offset;
            hs_res_320.auth_response = Malloc(read_size);
            memcpy(&hs_res_320.auth_response, pack.playload + read_offset, read_size);
        }
    }


    
    //auth switch request
    free(pack.playload);
    ReadPacket(fd, &pack);
    read_offset = 0;
    read_size = 0;
    auth_switch_rq as_req_pack;
    memset(&as_req_pack, 0, sizeof(auth_switch_rq));
    as_req_pack.status = pack.playload[0];
    read_offset += sizeof(as_req_pack.status);
    if(as_req_pack.status == 0xfe && pack.playload_length > read_offset){    //AuthSwitchRequest, OldAuthSwitchRequest length is 1 byte    
        read_size = GetNullStr(pack.playload +read_offset, &as_req_pack.plugin_name);
        read_offset += read_size;
        read_size = pack.playload_length - read_offset;
        as_req_pack.auth_plugin_data = Malloc(read_size);
        memcpy(as_req_pack.auth_plugin_data, pack.playload +read_offset, read_size);
    }

    //auth switch response
    free(pack.playload);
    ReadPacket(fd, &pack);//pack.playload contain encripted password

    //wait for OK packet or ERR packet



    //TODO make a memfree func for all structs
    free(pack.playload);

    HandshakeV10Free(&hs_pack);
    HSResponseFree(&hs_res);
    AuthSwitchRqFree(&as_req_pack);

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