#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>

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
#define MIN_OK_SIZE 7
#define MAX_EOF_SIZE 9
#define OK_HEADER 0x00
#define ERR_HEADER 0xff
#define EOF_HEADER 0xfe
#define LOCAL_INFILE_HEADER 0xfb



#define SERVER 0    //TODO подумать над дублированием определений
#define CLIENT 1    //


//Capability Flags
#define CLIENT_PLUGIN_AUTH 0x00080000
#define CLIENT_SECURE_CONNECTION 0x00008000
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#define CLIENT_CONNECT_WITH_DB 0x00000008
#define CLIENT_CONNECT_ATTRS 0x00100000
#define CLIENT_PROTOCOL_41 0x00000200
#define CLIENT_SSL 0x00000800
#define CLIENT_TRANSACTIONS 0x00002000
#define CLIENT_SESSION_TRACK 0x00800000
#define CLIENT_DEPRECATE_EOF 0x01000000

//status flags
#define SERVER_SESSION_STATE_CHANGED 0x4000
#define SERVER_MORE_RESULTS_EXISTS 0x0008


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

typedef struct command{
    __uint8_t id;
    u_char *playload;
}command;

typedef struct ok_pack{
    u_int8_t header;
    u_int64_t affected_rows;
    u_int64_t last_insert_id;
    //if capabilities & CLIENT_PROTOCOL_41 
    // else if capabilities & CLIENT_TRANSACTIONS
        // use only flags
    u_int16_t status_flags;
    u_int16_t warnings;
    //if capabilities & CLIENT_SESSION_TRACK
    u_char *info; //lenenc string else EOF string
        //if status_flags & SERVER_SESSION_STATE_CHANGED
    u_char *session_state_changes;

}ok_pack;

#pragma pack(push, 1)
typedef struct err_pack{
    u_int16_t error_code;
    //if capabilities & CLIENT_PROTOCOL_41
    char sql_state_marker;
    char sql_state[5]; //end if
    u_char *error_message; //eof string
}err_pack;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct column_definition_41{
    u_char *catalog;
    u_char *schema;
    u_char *table;
    u_char *org_table;
    u_char *name;
    u_char *org_name;
    u_char *default_values; //if command is COM_FIELD_LIST
    u_int64_t len_fixlen_fields;
    u_int16_t character_set;
    u_int32_t column_length;
    u_int8_t column_type;
    u_int16_t flags;
    u_int8_t decimals;
}column_definition_41;
#pragma pack(pop)

typedef u_char* string;
typedef string* row;

typedef struct resultset_row{
    row this;
    struct resultset_row *next;
}resultset_row;

typedef struct resultset{
    u_int64_t column_count;
    column_definition_41 *fields;
    resultset_row *rows;
    ok_pack eof;
    err_pack err;
}resultset;



void ReadPacket(int in_fd, sql_packet_bit *pack);
ssize_t Read(int fd, void *buf, size_t size_buf_element, size_t count);
int GetLenEncInt(u_char *buf, int64_t *result);
u_int64_t ReadLenIncStr(u_char *buf, u_char **str);
void *Malloc(size_t size);
void ConnAttrsFree(client_conn_attrs *pack);
void AuthSwitchRqFree(auth_switch_rq *pack);



void ReadField(u_char *playload, u_int32_t playload_length, column_definition_41 *pack){
    u_int64_t read_offset = 0;
    read_offset += ReadLenIncStr(playload + read_offset, &pack->catalog);
    read_offset += ReadLenIncStr(playload + read_offset, &pack->schema);
    read_offset += ReadLenIncStr(playload + read_offset, &pack->table);
    read_offset += ReadLenIncStr(playload + read_offset, &pack->org_table);
    read_offset += ReadLenIncStr(playload + read_offset, &pack->name);
    read_offset += ReadLenIncStr(playload + read_offset, &pack->org_name);
    u_char *ptr = (u_char*)pack;
    // for(int i = 0; i < 6; ++i){        
    //     read_offset += ReadLenIncStr(playload + read_offset, &ptr + (i*(sizeof(u_char*))));
    // }
    read_offset += GetLenEncInt(playload + read_offset, &pack->len_fixlen_fields);
    int offset = offsetof(column_definition_41, character_set);
    memcpy(ptr + offsetof(column_definition_41, character_set), playload + read_offset, 10);
    return;
}

void ReadRow(u_char *playload, u_int64_t column_count, resultset_row *row){
    u_int64_t read_offset = 0;
    row->this = Malloc(column_count * sizeof(*row->this));
    for(int i = 0; column_count > 0; i++, column_count--){
        read_offset += ReadLenIncStr(playload + read_offset, &(row->this[i]));        
    }
    return;
}

void ComRead(u_char *playload, u_int32_t playload_len, command *pack){
    memset(pack, 0, sizeof(command));
    pack->id = playload[0];
    pack->playload = Malloc(playload_len - sizeof(pack->id));
    memcpy(pack->playload, playload + sizeof(pack->id), playload_len - sizeof(pack->id));
    return;
}


/*filling the ERR_PACK struct
PLAYLOAD and PLAYLOAD_LEN is a pointer and length of incoming buffer,
PACK is a pointer to a ERR_PACK struct instance,
SRV_CAPABILITIES is a server capabilities flags variable
*/
void ReadErr(u_char *playload, u_int32_t playload_len, err_pack *pack, u_int32_t srv_capabilities){
    memset(pack, 0, sizeof(*pack));
    int64_t read_size = 0, read_offset = 1; //header exclude from struct but include in playload
    char *p_pack = (char *)pack;
    memcpy(p_pack, playload + read_offset, sizeof(pack->error_code));
    read_offset += sizeof(pack->error_code);
    if(srv_capabilities & CLIENT_PROTOCOL_41){
        read_size = sizeof(pack->sql_state_marker) + sizeof(pack->sql_state);
        memcpy(p_pack + offsetof(err_pack, sql_state_marker), playload + read_offset, read_size);
        read_offset += read_size;
    }
    read_size = playload_len - read_offset;
    pack->error_message = Malloc(read_size);
    memcpy(pack->error_message, playload + read_offset, read_size);
}

/*filling the OK_PACK struct
PLAYLOAD and PLAYLOAD_LEN is a pointer and length of incoming buffer,
PACK is a pointer to a OK_PACK struct instance,
SRV_CAPABILITIES is a server capabilities flags variable
*/
void ReadOk(u_char *playload, u_int32_t playload_len, ok_pack *pack, u_int32_t srv_capabilities){
    memset(pack, 0, sizeof(*pack));
    int64_t read_size = 0, read_offset = 0;
    pack->header = playload[0];    
    read_offset += sizeof(pack->header);
    read_size = GetLenEncInt(playload+read_offset, &(pack->affected_rows));
    if(read_size < 0){
        fprintf(stderr, "lenenc read error to ok_pack.affected_rows\n");
        return;
    }    
    read_offset += read_size;
    read_size = GetLenEncInt(playload+read_offset, &(pack->last_insert_id));
    if(read_size < 0){
        fprintf(stderr, "lenenc read error to ok_pack.last_insert_id\n");
        return;
    }    
    read_offset += read_size;
    if(srv_capabilities & CLIENT_PROTOCOL_41){
        read_size = sizeof(pack->status_flags);
        memcpy(&(pack->status_flags), 
                 playload + read_offset, 
                 read_size);
        read_offset += read_size;
        read_size = sizeof(pack->warnings);
        memcpy(&(pack->warnings), 
                 playload + read_offset, 
                 read_size);
        read_offset += read_size;
    }else if(srv_capabilities & CLIENT_TRANSACTIONS){
        read_size = sizeof(pack->status_flags);
        memcpy(&(pack->status_flags), 
                 playload + read_offset, 
                 read_size);
        read_offset += read_size;
    }
    if(read_offset < playload_len){ //TODO разобраться с вложенностью строк 
        if(srv_capabilities & CLIENT_SESSION_TRACK){
            read_offset += ReadLenIncStr(playload + read_offset, &(pack->info));
            if((pack->status_flags) & SERVER_SESSION_STATE_CHANGED){
                read_offset += ReadLenIncStr(playload + read_offset, &(pack->session_state_changes));
            }
        }else{
            read_size = playload_len - read_offset;
            pack->info = Malloc(read_size);
            memcpy(&(pack->info), playload + read_offset, read_size);
        }
    }
}

/*read and copy length encoded string from BUF to STR
*return num of bytes readed from BUF
*/
u_int64_t ReadLenIncStr(u_char *buf, u_char **str){
    u_int64_t length = 0;
    int offset = 0;
    offset = GetLenEncInt(buf, &length);
    if(offset < 0){
        if(length == 0xfb){
            u_char mes[] = "NULL";
            *str = Malloc(sizeof(mes));
            memcpy(*str, mes, sizeof(mes));
            return 1; 
        }else{
            fprintf(stderr, "GetLenIncStr error: can't define str length\n");
            return 0;
        }
    }else{
        if(length > 0){        
            u_char eos = '\0';
            *str = Malloc(length + sizeof(char));
            memcpy(*str, buf+offset, length);
            memcpy(*str + length, &eos, sizeof(u_char));
            return (u_int64_t)offset + length;
        }else{
            u_char mes[] = "NULL length string";
            *str = Malloc(sizeof(mes));
            memcpy(*str, mes, sizeof(mes));
            return (u_int64_t)offset + length;
        }
    }
}

/*read and copy length encoded integer from BUF to RESULT
*return num of bytes, readed from BUF,
or -1 if first byte of BUF equals 0xfb or 0xff
*/
int GetLenEncInt(u_char *buf, int64_t *result){
    int offset = 0;
    *result = 0;
    if(buf[0] < 0xfb){
        *result = buf[0];
        offset = 1;
    }else if(buf[0] == 0xfc){
        offset = 3;
        memcpy(result, buf+1, offset - 1);
    }else if(buf[0] == 0xfd){
        offset = 4;
        memcpy(result, buf+1, offset - 1);
    }else if(buf[0] == 0xfe){
        offset = 9;
        memcpy(result, buf+1, offset - 1);
    }else{
        *result = buf[0];
        //fprintf(stderr, "buffer is not contain a length encoded integer\nbuf[0] = %d\n", buf[0]);
        offset = -1;
    }
    return offset;
}

/*Get data from IN_FD stream and save it to struct PACK 
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
    int64_t read_offset = 0, read_size = 0;
    
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
    u_int16_t protocol_check = 0;
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
    auth_switch_rq as_req_pack;
    memset(&as_req_pack, 0, sizeof(auth_switch_rq));
    read_offset = 0;
    read_size = 0;        
    as_req_pack.status = pack.playload[0];
    read_offset += sizeof(as_req_pack.status);
    if(as_req_pack.status == 0xfe && pack.playload_length > read_offset){    //AuthSwitchRequest, OldAuthSwitchRequest length is 1 byte    
        read_size = GetNullStr(pack.playload +read_offset, &as_req_pack.plugin_name);
        read_offset += read_size;
        read_size = pack.playload_length - read_offset;
        as_req_pack.auth_plugin_data = Malloc(read_size);
        memcpy(as_req_pack.auth_plugin_data, pack.playload +read_offset, read_size);
    }
    

    //auth switch response or connection close
    while(1){ //wait for OK packet or ERR packet
        free(pack.playload);
        ReadPacket(fd, &pack);
        if(pack.sender == SERVER &&
           pack.playload_length >= MIN_OK_SIZE &&
           pack.playload[0] == OK_HEADER){
            ok_pack ok;
            ReadOk(pack.playload, pack.playload_length, &ok, server_capabilities);
            //logok(ok);    //TODO make implementation
            //FreeOK(ok);   //TODO make implementation
            break;
        }else if(pack.sender == SERVER &&
                 pack.playload[0] == ERR_HEADER){
            err_pack err;
            ReadErr(pack.playload, pack.playload_length, &err, server_capabilities);  
            //logerr(err);  //TODO make implementation
            //FreeErr(err); //TODO make implementation
            break;
        }
        
    }
    free(pack.playload);


    ///Command phase
    ReadPacket(fd, &pack);
    if(pack.sender == CLIENT){
        command com;
        ComRead(pack.playload, pack.playload_length, &com);
        free(pack.playload);
        if(com.id == COM_QUERY){    //COM_QUERY response handler
            ReadPacket(fd, &pack);
            if(pack.sender == SERVER &&
               pack.playload_length >= MIN_OK_SIZE &&
               pack.playload[0] == OK_HEADER){
                ok_pack ok;
                ReadOk(pack.playload, pack.playload_length, &ok, server_capabilities);
                //logok(ok);    //TODO make implementation
                //FreeOK(ok);   //TODO make implementation
                free(pack.playload);
            }else if(pack.sender == SERVER &&
                     pack.playload_length < MAX_EOF_SIZE &&
                     pack.sequence_id > 1 &&
                     pack.playload[0] == EOF_HEADER){
                ok_pack ok;
                ReadOk(pack.playload, pack.playload_length, &ok, server_capabilities);
                //logok(ok);    //TODO make implementation
                //FreeOK(ok);   //TODO make implementation
                free(pack.playload);
            }else if(pack.sender == SERVER &&
                     pack.playload[0] == ERR_HEADER){
                err_pack err;
                ReadErr(pack.playload, pack.playload_length, &err, server_capabilities);  
                //logerr(err);  //TODO make implementation
                //FreeErr(err); //TODO make implementation
                free(pack.playload);
            }else if(pack.sender == SERVER &&
                     pack.playload[0] == LOCAL_INFILE_HEADER){
                //TODO make handler
            }else{  //ProtocolText::resultset
                bool end_resultset = false, end_row = false;
                resultset q_res;
                memset(&q_res, 0, sizeof(q_res));
                while(!end_resultset){                   
                    GetLenEncInt(pack.playload, &q_res.column_count);
                    free(pack.playload);
                    q_res.fields = Malloc(q_res.column_count * sizeof(*q_res.fields));                                       
                    for(int i = 0; i < q_res.column_count; ++i){
                        ReadPacket(fd, &pack);
                        ReadField(pack.playload, pack.playload_length, &q_res.fields[i]); //TODO make implementation
                        free(pack.playload);
                    }
                    if(!(server_capabilities & CLIENT_DEPRECATE_EOF)){ //??? нужен он тут?
                        ok_pack ok;
                        ReadPacket(fd, &pack);
                        ReadOk(pack.playload, pack.playload_length, &ok, server_capabilities);                          
                        free(pack.playload);
                        //logok(ok);    //TODO make implementation
                        //FreeOK(ok);   //TODO make implementation
                    }
                    resultset_row **head = &q_res.rows;
                    while(!end_row){
                        ReadPacket(fd, &pack);
                        if(pack.playload[0] == ERR_HEADER){                        
                            ReadErr(pack.playload, pack.playload_length, &q_res.err, server_capabilities);
                            free(pack.playload);                             
                            end_row = true;
                        }else if(pack.playload_length < MAX_EOF_SIZE &&
                                 pack.playload[0] == EOF_HEADER){                        
                            ReadOk(pack.playload, pack.playload_length, &q_res.eof, server_capabilities);                          
                            free(pack.playload); 
                            end_row = true;                        
                        }else{
                            *head = Malloc(sizeof(resultset_row));
                            ReadRow(pack.playload, q_res.column_count, *head); //TODO make implementation
                            free(pack.playload);
                            head = &((*head)->next);
                            
                        }
                    }
                    if(!(q_res.eof.status_flags & SERVER_MORE_RESULTS_EXISTS)){
                        end_resultset = true;
                    }
                }
            }

        }
    }else{
        printf("Unable to interpret packet\n"); //TODO add dumping pack playload to file
    }







    //TODO make a memfree func for all structs
    

    HandshakeV10Free(&hs_pack);
    HSResponseFree(&hs_res);
    AuthSwitchRqFree(&as_req_pack);
    exit(0);
}