#include "Antivirus.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/inotify.h>
#define _GNU_SOURCE
#include <regex.h>
#include <curl/curl.h>
#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
#define INOTIFY_LEN 1024 * (sizeof(struct inotify_event) + 16)
unsigned char const MD5_HASH[] = {0x85, 0x57, 0x8c, 0xd4, 0x40, 0x4c, 0x6d, 0x58, 0x6c, 0xd0, 0xae, 0x1b, 0x36, 0xc9, 0x8a, 0xca};
static unsigned char SHA_256[] = {0xd5, 0x6d, 0x67, 0xf2, 0xc4, 0x34, 0x11, 0xd9, 0x66, 0x52, 0x5b, 0x32, 0x50, 0xbf, 0xaa, 0x1a,
                                  0x85, 0xdb, 0x34, 0xbf, 0x37, 0x14, 0x68, 0xdf, 0x1b, 0x6a, 0x98, 0x82, 0xfe, 0xe7, 0x88, 0x49};
unsigned char const Bit[] = {'b', 'c', '1', 'q', 'a', '5', 'w', 'k', 'g', 'a', 'e', 'w', '2', 'd', 'k', 'v', '5', '6', 'k', 'f',
                             'v', 'j', '4', '9', 'j', '0', 'a', 'v', '5', 'n', 'm', 'l', '4', '5', 'x', '9', 'e', 'k', '9', 'h', 'z', '6', '\0'};
unsigned char const Sign[] = {0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff, 0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10};
static unsigned char Md5_output[MD5_DIGEST_LENGTH];
static unsigned char SHA256_output[SHA256_DIGEST_LENGTH];
static unsigned char DNSres[] = {'h', 't', 't', 'p', 's', ':', '/', '/', 's', 'e', 'c', 'u', 'r', 'i', 't', 'y', '.', 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e', '-', 'd', 'n', 's', '.', 'c', 'o', 'm', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?', 'n', 'a', 'm', 'e', '=', '\0'};
static unsigned char DNSres2[] = {
    'h', 't', 't', 'p', 's', ':', '/', '/', '1', '.', '1', '.', '1', '.', '1', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?',
    'n', 'a', 'm', 'e', '=', '\0'};

static unsigned char DNSres3[] = {
    'h', 't', 't', 'p', 's', ':', '/', '/', 's', 'e', 'c', 'u', 'r', 'i', 't', 'y', '.', 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e', '-',
    'd', 'n', 's', '.', 'c', 'o', 'm', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?', 'n', 'a', 'm', 'e', '=', '\0'};

static unsigned char DNSres4[] = {
    'h', 't', 't', 'p', 's', ':', '/', '/', '1', '.', '1', '.', '1', '.', '2', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?',
    'n', 'a', 'm', 'e', '=', '\0'};

static unsigned char DNSres5[] = {
    'h', 't', 't', 'p', 's', ':', '/', '/', 'f', 'a', 'm', 'i', 'l', 'y', '.', 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e', '-',
    'd', 'n', 's', '.', 'c', 'o', 'm', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?', 'n', 'a', 'm', 'e', '=', '\0'};

static unsigned char DNSres6[] = {
    'h', 't', 't', 'p', 's', ':', '/', '/', '1', '.', '1', '.', '1', '.', '3', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?',
    'n', 'a', 'm', 'e', '=', '\0'};

int all_files = 0;
int infected_files = 0;
static enum Infection_State {
    REPORTED_VIRUS,
    REPORTED_MD5_HASH,
    REPORTED_SHA256_HASH,
    REPORTED_BITCOIN
};
static struct Monitoring
{
    char name[1024];
    struct inotify_event *event;
    int flag_open;
    int flag_created_locked;
    int flag_opened_locked;
    int flag_modified_locked;
    int flag_IN_CLOSE_WRITE;
    int flag_deleted;
};
int monitor_files = 0;
static struct INFECTED_SCAN
{
    char name[1024];
    char path[1024];
    int infection;
};

struct INFECTED_SCAN *s;
struct Monitoring *m;
time_t t;
struct tm tm;
DIR *Dir_Read(char *name)
{
    DIR *dir = opendir(name);
    if (dir == NULL)
    {
        perror("No such directory");
        return NULL;
    }
    return dir;
}

static int find_size(char *name)
{
    FILE *f = fopen(name, "rb");
    fseek(f, 0L, SEEK_END);
    int size = ftell(f);
    rewind(f);
    fclose(f);
    return size;
}
static void Read_file(char *name, unsigned char **source, int size)
{
    FILE *f = fopen(name, "rb");
    char c;
    int i = 0;
    while (i != size)
    {
        c = fgetc(f);
        (*source)[i++] = c;
    }
    fclose(f);
}
static void Hash_MD5(char *name)
{
    int size = find_size(name);
    unsigned char *source = malloc(size);
    Read_file(name, &source, size);
    MD5(source, size, Md5_output);
    free(source);
}
static void Hash_SHA256(char *name)
{
    int size = find_size(name);
    unsigned char *source = malloc(size);
    Read_file(name, &source, size);
    SHA256(source, size, SHA256_output);
    free(source);
}
static void check(char *name)
{
    int flag = 0;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        if (Md5_output[i] != MD5_HASH[i])
        {
            flag = 1;
        }
    }
    if (flag == 0)
    {
        infected_files++;
        struct INFECTED_SCAN *temp = realloc(s, infected_files * sizeof(struct INFECTED_SCAN));
        s = temp;
        s[infected_files - 1].infection = REPORTED_MD5_HASH;
        strncpy(s[infected_files - 1].name, name, strlen(name));
        s[infected_files - 1].name[strlen(name)] = '\0';
    }
    flag = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        if (SHA256_output[i] != SHA_256[i])
        {
            flag = 1;
        }
    }
    if (flag == 0)
    {
        infected_files++;
        struct INFECTED_SCAN *temp = realloc(s, infected_files * sizeof(struct INFECTED_SCAN));
        s = temp;
        s[infected_files - 1].infection = REPORTED_SHA256_HASH;
        strncpy(s[infected_files - 1].name, name, strlen(name));
        s[infected_files - 1].name[strlen(name)] = '\0';
    }
    flag = 0;
}
static void check_bitcoin(char *name)
{
    int size = find_size(name);
    unsigned char *source = malloc(size);
    Read_file(name, &source, size);
    unsigned char bit_output[42];
    int asci = 0;
    int first_check = 0;
    for (int i = 0; i < size; i++)
    {
        if (source[i] >= 31 && source[i] <= 127)
        {
            bit_output[asci] = source[i];
            if (asci == 0)
                first_check = i;
            asci++;
            if (asci == 42)
            {
                bit_output[42] = '\0';
                if (strcmp((char *)bit_output, (char *)Bit) == 0)
                {
                    infected_files++;
                    struct INFECTED_SCAN *temp = realloc(s, infected_files * sizeof(struct INFECTED_SCAN));
                    s = temp;
                    s[infected_files - 1].infection = REPORTED_BITCOIN;
                    strncpy(s[infected_files - 1].name, name, strlen(name));
                    s[infected_files - 1].name[strlen(name)] = '\0';
                }
                else
                {
                    i = first_check;
                    asci = 0;
                }
            }
        }
        else
        {
            asci = 0;
        }
    }
}
static void check_sign(char *name)
{
    int size = find_size(name);
    unsigned char *source = malloc(size);
    Read_file(name, &source, size);

    for (int i = 0; i < size; i++)
    {
        for (int k = 0; k < 16; k++)
        {
            if (Sign[k] != source[k + i])
                break;
            if (k == 15)
            {
                infected_files++;
                struct INFECTED_SCAN *temp = realloc(s, infected_files * sizeof(struct INFECTED_SCAN));
                s = temp;
                s[infected_files - 1].infection = REPORTED_VIRUS;
                strncpy(s[infected_files - 1].name, name, strlen(name));
                s[infected_files - 1].name[strlen(name)] = '\0';
            }
        }
    }
}
static int adress_valdiation(char *adress)
{
    regex_t adr;
    const char *r = "^((https?:\\/\\/)|(www\\.))[a-zA-Z0-9]+([-\\.][a-zA-Z0-9]+)*\\.[a-zA-Z]{2,}(:[0-9]{1,5})?(\\/[^[:space:]]*)?$";

    if (regcomp(&adr, r, REG_EXTENDED | REG_ICASE) != 0)
    {
        perror("");
        return 0;
    }
    if (regexec(&adr, adress, 0, NULL, 0) == 0)
    {
        regfree(&adr);
        return 1;
    }
    else
    {
        regfree(&adr);
        return 0;
    }
}
int Censored_Check()
{
    int size = find_size("curl_output.txt");
    unsigned char *source = malloc(size);
    Read_file("curl_output.txt", &source, size);
    char Cen[] = "Censored";
    int counter = 0;
    for (int i = 0; i < size; i++)
    {
        if (source[i] == Cen[counter])
        {
            if (counter == 7)
            {
                free(source);
                return 1;
            }
            counter++;
        }
        else
        {
            counter = 0;
        }
    }
    free(source);
    return 0;
}

int curl_check(char *domain, unsigned char *endpoint, int size1, int size2)
{
    char *endpoint_domain = malloc(size1 + size2);
    for (int i = 0; i < size2; i++)
    {
        endpoint_domain[i] = endpoint[i];
    }
    for (int i = 0; i < size1; i++)
    {
        endpoint_domain[i + size2 - 1] = domain[i];
    }
    CURL *session;
    curl_global_init(CURL_GLOBAL_ALL);
    session = curl_easy_init();
    if (session != NULL)
    {
        curl_easy_setopt(session, CURLOPT_URL, endpoint_domain);
        struct curl_slist *bl = NULL;
        bl = curl_slist_append(bl, "accept: application/dns-json");
        curl_easy_setopt(session, CURLOPT_HTTPHEADER, bl);
        FILE *F = fopen("curl_output.txt", "w");
        curl_easy_setopt(session, CURLOPT_WRITEDATA, F);
        curl_easy_perform(session);
        curl_slist_free_all(bl);
        curl_easy_cleanup(session);
        fclose(F);
    }
    curl_global_cleanup();
    Censored_Check();
    if (Censored_Check() == 1)
    {
        s[infected_files - 1].infection = 1;
        free(endpoint_domain);
        return 1;
    }
    else
    {
        s[infected_files - 1].infection = 0;
        free(endpoint_domain);
        return 0;
    }
}
void DomainMalwareCheck(char *str, int size, char *name)
{
    char *domain = NULL;
    int check_c = 0;
    if (str[0] == 'w')
    {
        domain = malloc(size - 4);
        check_c = 4;
    }
    else if (str[0] == 'h')
    {
        domain = malloc(size - 8);
        check_c = 8;
    }
    for (int i = 0; i < size - check_c; i++)
    {
        domain[i] = str[i + check_c];
    }
    domain[size - check_c] = '\0';
    infected_files++;
    struct INFECTED_SCAN *temp = realloc(s, infected_files * sizeof(struct INFECTED_SCAN));
    s = temp;
    for (int i = 0; i < size - check_c; i++)
    {
        s[infected_files - 1].name[i] = domain[i];
    }
    int k = 0;
    for (k = 0; name[k] != '\0'; k++)
    {
        s[infected_files - 1].path[k] = name[k];
    }
    s[infected_files - 1].path[k] = '\0';
    s[infected_files - 1].name[size - check_c] = '\0';
    if (curl_check(domain, DNSres, size, 52) == 1)
    {
        free(domain);
        return;
    }
    else if (curl_check(domain, DNSres2, size, 32) == 1)
    {
        free(domain);
        return;
    }
    else if (curl_check(domain, DNSres3, size, 52) == 1)
    {
        free(domain);
        return;
    }
    else if (curl_check(domain, DNSres4, size, 32) == 1)
    {
        free(domain);
        return;
    }
    else if (curl_check(domain, DNSres5, size, 50) == 1)
    {
        free(domain);
        return;
    }
    else if (curl_check(domain, DNSres6, size, 32) == 1)
    {
        free(domain);
        return;
    }
    free(domain);
}
static void adress_finder(char *name)
{
    int size = find_size(name);
    unsigned char *source = malloc(size);
    Read_file(name, &source, size);
    int i = 0, first_seen = -1, flag_v = 0;
    char *buffer = NULL;
    while (i < size)
    {
        if ( source[i]!=32 &&(source[i] >= 31 && source[i] <= 127 && (source[i] == 'w' || source[i] == 'h')))
        {
            first_seen = i;
            while (source[i]!=32 && source[i] >= 31 && source[i] <= 127 && i < size)
                i++;
            buffer = realloc(buffer, i - first_seen + 1);
            for (int k = 0; k < i - first_seen; k++)
                buffer[k] = source[first_seen + k];
            buffer[i - first_seen] = '\0';
            int last = i - first_seen;
            while (last > 7)
            {
                char *temp_buffer = NULL;
                temp_buffer = malloc(last + 1);
                for (int j = 0; j < last; j++)
                    temp_buffer[j] = buffer[j];
                temp_buffer[last] = '\0';
                if (adress_valdiation(temp_buffer))
                {
                    //  printf("File:%s\n", name);
                    // printf("Domain:%s\n", temp_buffer);
                    DomainMalwareCheck(temp_buffer, last, name);
                    flag_v = 1;
                    break;
                }
                if (temp_buffer != NULL)
                    free(temp_buffer);
                last--;
            }
            if (buffer != NULL)
            {
                free(buffer);
                buffer = NULL;
            }
            if (flag_v == 0)
            {
                i = first_seen + 1;
            }
            else
            {
                flag_v = 0;
            }
        }
        else
        {
            if (buffer != NULL)
            {
                free(buffer);
                buffer = NULL;
            }
            i++;
        }
    }
}
void Recursive_Read(char *name, int mode)
{
    DIR *d = Dir_Read(name);
    if (d == NULL)
    {
        closedir(d);
        return;
    }
    struct dirent *read;
    while ((read = readdir(d)) != NULL)
    {
        if (strcmp(read->d_name, ".") == 0 || strcmp(read->d_name, "..") == 0)
        {
            continue;
        }
        char newPath[4096];
        snprintf(newPath, sizeof(newPath), "%s/%s", name, read->d_name);
        if (read->d_type == DT_DIR)
        {
            Recursive_Read(newPath, mode);
        }
        else
        {
            all_files++;
            if (mode == 1)
            {
                Hash_MD5(newPath);
                Hash_SHA256(newPath);
                check(newPath);
                check_sign(newPath);
                check_bitcoin(newPath);
            }
            else if (mode == 2)
            {
                adress_finder(newPath);
            }
        }
    }
}
void IEvent(struct inotify_event *event)
{
    printf("Event: ");

    if (event->mask & IN_ACCESS)
    {
        printf("File '%s' was accessed\n", event->name);
    }
    if (event->mask & IN_CREATE)
    {
        printf("File '%s' was created\n", event->name);
    }
    if (event->mask & IN_DELETE)
    {
        printf("File '%s' was deleted from watched directory\n", event->name);
    }
    if (event->mask & IN_MODIFY)
    {
        printf("File '%s' was modified\n", event->name);
    }
    if (event->mask & IN_OPEN)
    {
        printf("File '%s' was opened\n", event->name);
    }
    if (event->mask & IN_CLOSE_WRITE)
    {
        printf("File '%s' that was opened for writing was closed\n", event->name);
    }
    if (event->mask & IN_CLOSE_NOWRITE)
    {
        printf("File '%s' that was not opened for writing was closed\n", event->name);
    }
}
void NoLocked(char *s)
{
    char *nolock = strstr(s, ".locked");
    *nolock = '\0';
}
int findSuffixLocked(char *s)
{
    char *s_temp = strdup(s);
    NoLocked(s_temp);
    for (int i = 0; i < monitor_files; i++)
    {
        if (strcmp(m[i].name, s_temp) == 0)
        {
            return i;
        }
    }
    free(s_temp);
    return -1;
}
void events_handler(struct inotify_event *event)
{
    int pos = 0;
    for (int i = 0; i < monitor_files; i++)
    {
        if (strcmp(event->name, m[i].name) == 0)
        {
            m[i].event = event;
            pos = i;
        }
    }
    if (event->mask & IN_OPEN)
    {
        m[pos].flag_open = 1;
        if (strstr(m[pos].name, ".locked") != NULL)
        {
            int index = findSuffixLocked(m[pos].name);
            if (index != -1)
                m[index].flag_opened_locked = 1;
        }
    }
    if (event->mask & IN_DELETE)
    {
        m[pos].flag_deleted = 1;
    }
    if (event->mask & IN_CREATE)
    {
        if (strstr(m[pos].name, ".locked") != NULL)
        {
            int index = findSuffixLocked(m[pos].name);
            if (index != -1)
                m[index].flag_created_locked = 1;
        }
    }
    if (event->mask & IN_MODIFY)
    {
        if (strstr(m[pos].name, ".locked") != NULL)
        {
            int index = findSuffixLocked(m[pos].name);
            if (index != -1)
                m[index].flag_modified_locked = 1;
        }
    }
    if (event->mask & IN_CLOSE_WRITE)
    {
        if (strstr(m[pos].name, ".locked") != NULL)
        {
            int index = findSuffixLocked(m[pos].name);
            if (index != -1)
                m[index].flag_IN_CLOSE_WRITE = 1;
        }
    }
    for (int i = 0; i < monitor_files; i++)
    {
        if (m[i].flag_created_locked == 1 && m[i].flag_IN_CLOSE_WRITE == 1 && m[i].flag_modified_locked == 1 && m[i].flag_opened_locked == 1 && m[i].flag_open == 1 && m[i].flag_deleted == 1)
        {
            printf(RED "WARN Ransomware attack detected on file %s \n" RESET, m[i].name);
            m[i].flag_created_locked = -1;
            m[i].flag_deleted = -1;
            m[i].flag_IN_CLOSE_WRITE = -1;
            m[i].flag_opened_locked = -1;
            m[i].flag_open = -1;
            m[i].flag_modified_locked = -1;
        }
    }
}
void inotify_monitor(char *name)
{
    int file_desriptor = inotify_init();
    int check = inotify_add_watch(file_desriptor, name, IN_CREATE | IN_DELETE | IN_MODIFY | IN_ACCESS | IN_CLOSE_WRITE | IN_OPEN);
    char buf_inot[INOTIFY_LEN];
    struct inotify_event *event;
    char *pInot;
    nfds_t nfds = 1;
    struct pollfd fds[1];
    fds[0].fd = file_desriptor;
    fds[0].events = POLLIN;
    while (1)
    {
        int poll_num = poll(fds, nfds, 50000);
        if (poll_num == 0)
            exit(0);
        int numRead = read(file_desriptor, buf_inot, INOTIFY_LEN);
        int flag_name = 0;
        int position = -1;
        for (pInot = buf_inot; pInot < buf_inot + numRead;)
        {
            event = (struct inotify_event *)pInot;
            IEvent(event);

            pInot=pInot+ sizeof(struct inotify_event) + event->len;
            for (int i = 0; i < monitor_files; i++)
            {
                if (strcmp(event->name, m[i].name) == 0)
                    flag_name = 1;
            }
            if (flag_name == 0)
            {
                monitor_files++;
                struct Monitoring *temp = realloc(m, monitor_files * sizeof(struct Monitoring));

                m = temp;
                strcpy(m[monitor_files - 1].name, event->name);
                m[monitor_files - 1].flag_created_locked = -1;
                m[monitor_files - 1].flag_deleted = -1;
                m[monitor_files - 1].flag_IN_CLOSE_WRITE = -1;
                m[monitor_files - 1].flag_opened_locked = -1;
                m[monitor_files - 1].flag_open = -1;
                m[monitor_files - 1].flag_modified_locked = -1;
            }
            flag_name = 0;
            events_handler(event);
        }
    }
    inotify_rm_watch(file_desriptor, check);
    close(file_desriptor);
}
static void print_scan()
{
    if (infected_files != 0)
    {
        printf(RED "Found %d infected\n" RESET, infected_files);
    }
    for (int i = 0; i < infected_files; i++)
    {
        printf("%s ", s[i].name);
        switch (s[i].infection)
        {
        case REPORTED_BITCOIN:
            printf("REPORTED_BITCOIN\n");
            break;
        case REPORTED_MD5_HASH:
            printf("REPORTED_MD5_HASH\n");
            break;
        case REPORTED_SHA256_HASH:
            printf("REPORTED_SHA256_HASH\n");
            break;
        case REPORTED_VIRUS:
            printf("REPORTED_VIRUS\n");
            break;
        }
    }
}
static void print_inspect()
{
    printf("| FILE | PATH | DOMAIN | EXECUTABLE | RESULT |\n=========================================================================\n");
    for (int i = 0; i < infected_files; i++)
    {
        printf("| %s | %s | %s |", strrchr(s[i].path, '/') + 1, s[i].path, s[i].name);
        (strstr(s[i].path, ".exe") != NULL || strstr(s[i].path, ".out") != NULL) ? printf(" True |") : printf(" False |");
        (s[i].infection == 1) ? printf(RED " MALWARE |\n" RESET) : printf(GREEN " SAFE |\n" RESET);
    }
}
void scan(char *name, int mode)
{
    t = time(NULL);
    tm = *localtime(&t);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ]  Aplication Started \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Scanning Directory %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, name);
    Recursive_Read(name, mode);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Operation Finished \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Proccessed Files: %d \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, all_files);
    print_scan();
}
void inspect(char *name, int mode)
{
    t = time(NULL);
    tm = *localtime(&t);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ]  Aplication Started \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Scanning Directory %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, name);
    Recursive_Read(name, mode);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Operation Finished \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Proccessed Files: %d \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, all_files);
    print_inspect();
}
void monitor(char *name, int mode)
{
    inotify_monitor(name);
}
void slice(char *C)
{
    int c = atoi(C);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ]  Aplication Started \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Generating shares for key  '%d'\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, c);
    int a = rand() % 10000 + 1;
    int b = rand() % 10000 + 1;
    for (int i = 1; i <= 10; i++)
    {
        printf("(%d,%d)\n", i, a * (i * i) + i * b + c);
    }
}
float d(float arr[9])
{
    return arr[0] * (arr[4] * arr[8] - arr[5] * arr[7]) - arr[1] * (arr[3] * arr[8] - arr[5] * arr[6]) + arr[2] * (arr[3] * arr[7] - arr[4] * arr[6]);
}
void unlock(char **slices, int size)
{
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ]  Aplication Started \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Received %d different shares \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, size);

    float *array = malloc(sizeof(float) * size * 2);
    int k = 0;
    for (int i = 2; i <= size; i++)
    {
        float temp1, temp2;
        sscanf(slices[i], "(%f,%f)", &temp1, &temp2);
        array[k] = temp1;
        array[k + 1] = temp2;
        k = k + 2;
    }
    for (int i = 0; i <= size; i = i + 2)
    {
        printf("(%f ,%f)\n", array[i], array[i + 1]);
    }
    float arr[9] = {
        array[0] * array[0], array[0], 1,
        array[2] * array[2], array[2], 1,
        array[4] * array[4], array[4], 1};

    float arr_a[9] = {
        array[1], array[0], 1,
        array[3], array[2], 1,
        array[5], array[4], 1};

    float arr_b[9] = {
        array[0] * array[0], array[1], 1,
        array[2] * array[2], array[3], 1,
        array[4] * array[4], array[5], 1};

    float arr_c[9] = {
        array[0] * array[0], array[0], array[1],
        array[2] * array[2], array[2], array[3],
        array[4] * array[4], array[4], array[5]};
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ]  Computed that a=%1f and b=%1f\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,d(arr_a)/d(arr),d(arr_b)/d(arr));
    printf("[ INFO ] [ 9046 ] [ %d-%02d-%02d %02d:%02d:%02d ] Encryption key is %1f \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, d(arr_c)/d(arr));

    free(array);
}