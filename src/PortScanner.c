#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Iphlpapi.lib")
#define MAX_PORT 65535
#define DEFAULT_SCAN_TIMEOUT_MS 100
#define PROGRESS_BAR_WIDTH 43

typedef enum {
    SCAN_TCP_CONNECT,
    SCAN_TCP_SYN,
    SCAN_UDP
} ScanType;

char ip[16] = "";
int start_port = -1, end_port = -1;
ScanType scan_type = SCAN_TCP_SYN;
int scan_timeout_ms = DEFAULT_SCAN_TIMEOUT_MS;

void clear_screen() {
    system("cls");
}

void set_cursor_pos(int x, int y) {
    COORD coord = {x, y};
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

void hide_cursor() {
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);
}

void show_cursor() {
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);
    cursorInfo.bVisible = TRUE;
    SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);
}

void draw_progress(int percent) {
     int pos = (int)(PROGRESS_BAR_WIDTH * percent / 100);
    set_cursor_pos(0, 8);
    printf("    [");
    for (int i = 0; i < PROGRESS_BAR_WIDTH; ++i) {
        printf(i < pos ? "#" : " ");
    }
    printf("] %d%%", percent);
    fflush(stdout);
}

int is_valid_ip(const char* ip_str) {
    struct sockaddr_in sa;
    return InetPton(AF_INET, ip_str, &(sa.sin_addr)) == 1;
}

int connect_with_timeout(SOCKET sock, struct sockaddr_in* addr, int timeout_ms) {
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    int res = connect(sock, (struct sockaddr*)addr, sizeof(*addr));
    if (res == 0) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        return 0;
    }
    else if (WSAGetLastError() != WSAEWOULDBLOCK) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        return -1;
    }
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    res = select(0, NULL, &writeSet, NULL, &tv);
    if (res <= 0) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        return -1;
    }
    int err = 0;
    int len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    return err == 0 ? 0 : -1;
}

int syn_scan(SOCKET sock, struct sockaddr_in* addr, int timeout_ms) {
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    int res = connect(sock, (struct sockaddr*)addr, sizeof(*addr));
    if (res == 0) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        closesocket(sock);
        return 1;
    }
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    res = select(0, NULL, &writeSet, NULL, &tv);
    if (res > 0) {
        int error = 0;
        int len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        closesocket(sock);
        return (error == 0) ? 1 : 0;
    }
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    closesocket(sock);
    return 0;
}

int udp_scan(SOCKET sock, struct sockaddr_in* addr, int timeout_ms) {
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    char buffer[1] = {0};
    int res = sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)addr, sizeof(*addr));
    if (res == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAECONNREFUSED) {
            return 0;
        }
        return -1;
    }
    char recv_buffer[128];
    struct sockaddr_in from;
    int from_len = sizeof(from);
    res = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&from, &from_len);
    if (res == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAETIMEDOUT) {
            return 1;
        }
        return 0;
    }
    return 1;
}

void scan_ports() {
    if (strlen(ip) == 0) {
        printf("\n     Mistake: The IP address is not specified!\n");
        printf("\n     Press any key to return...");
        _getch();
        return;
    }
    if (start_port == -1 || end_port == -1) {
        start_port = 1;
        end_port = 1024; 
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    InetPton(AF_INET, ip, &(addr.sin_addr));
    int total_ports = end_port - start_port + 1;
    int current = 0;
    int open_ports = 0;
    int open_ports_list[1024];
    clear_screen();
    printf("    ╔══════════════════════════════════════════════╗\n");
    printf("    ║                   SCANNING                   ║\n");
    printf("    ╚══════════════════════════════════════════════╝\n");
    printf("     IP: %s\n", ip);
    printf("     Ports: %d-%d\n", start_port, end_port);
    printf("     Scan type: ");
    switch(scan_type) {
        case SCAN_TCP_CONNECT: printf("TCP Connect\n"); break;
        case SCAN_TCP_SYN: printf("TCP SYN\n"); break;
        case SCAN_UDP: printf("UDP\n"); break;
    }
    printf("     Timeout: %d ms\n", scan_timeout_ms);
    printf("    -------------------------------------------------\n");
    hide_cursor();
    for (int port = start_port; port <= end_port; ++port) {
        SOCKET sock;
        if (scan_type == SCAN_UDP) {
            sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        } else {
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }
        if (sock == INVALID_SOCKET) continue;
        addr.sin_port = htons(port);
        int result = -1;
        switch(scan_type) {
            case SCAN_TCP_CONNECT:
                result = connect_with_timeout(sock, &addr, scan_timeout_ms);
                break;
            case SCAN_TCP_SYN:
                result = syn_scan(sock, &addr, scan_timeout_ms);
                break;
            case SCAN_UDP:
                result = udp_scan(sock, &addr, scan_timeout_ms);
                break;
        }
        if (result == 1) { 
            open_ports_list[open_ports++] = port;
            set_cursor_pos(0, 9 + open_ports);
            printf("    Port %-5d [OPEN]", port);
            if (scan_type == SCAN_UDP) {
                struct servent* sv = getservbyport(htons(port), "udp");
                if (sv) printf(" (%s)", sv->s_name);
            } else {
                struct servent* sv = getservbyport(htons(port), "tcp");
                if (sv) printf(" (%s)", sv->s_name);
            }
            printf("\n");
        }
        if (scan_type != SCAN_TCP_SYN) {
            closesocket(sock);
        }
        current++;
        draw_progress((current * 100) / total_ports);
        printf("\n    -------------------------------------------------\n");
    }
    show_cursor(); 
    set_cursor_pos(0, 9 + open_ports + 2); 
    printf("\n     The scan is complete! Found open ports: %d\n", open_ports);
    printf("     Press any key to return to the menu...");
    _getch();
}

void set_scan_type() {
    clear_screen();
    printf("    ╔══════════════════════════════════════════════╗\n");
    printf("    ║            CHOOSING THE SCAN TYPE            ║\n");
    printf("    ╚══════════════════════════════════════════════╝\n\n");
    printf("     1. TCP Connect\n");
    printf("     2. TCP SYN\n");
    printf("     3. UDP\n");
    printf("\n     Select the scan type (1-3): ");
    int choice;
    if (scanf("%d", &choice) != 1) {
        while (getchar() != '\n');
        return;
    }
    switch(choice) {
        case 1: scan_type = SCAN_TCP_CONNECT; break;
        case 2: scan_type = SCAN_TCP_SYN; break;
        case 3: scan_type = SCAN_UDP; break;
        default:
            printf("\n     Wrong choice! TCP SYN is installed.\n");
            scan_type = SCAN_TCP_SYN;
            break;
    }
    printf("\n     Press any key to continue...");
    _getch();
}

void set_scan_timeout() {
    clear_screen();
    printf("    ╔══════════════════════════════════════════════╗\n");
    printf("    ║             SETTING THE TIMEOUT              ║\n");
    printf("    ╚══════════════════════════════════════════════╝\n\n");
    printf("     Current timeout: %d ms\n", scan_timeout_ms);
    printf("     Enter a new timeout (in milliseconds, 100-5000): ");
    int new_timeout;
    if (scanf("%d", &new_timeout) != 1) {
        while (getchar() != '\n');
        printf("\n     Input error!\n");
    } else {
        if (new_timeout >= 100 && new_timeout <= 5000) {
            scan_timeout_ms = new_timeout;
            printf("\n     The timeout has been set successfully!\n");
        } else {
            printf("\n     Incorrect value! Acceptable range: 100-5000 ms\n");
        }
    }
    printf("\n     Press any key to continue...");
    _getch();
}

void show_menu() {
    clear_screen();
    printf("    ╔══════════════════════════════════════════════╗\n");
    printf("    ║                 PORT SCANNER                 ║\n");
    if (strlen(ip) !=0 ){
        printf("    ╠══════════════════════════════════════════════╣\n");
        printf("    ║  IP:  %-34s     ║\n", ip);
    }
    if (start_port > 0 && end_port > 0) {
        if (strlen(ip) ==0 ){
            printf("    ╠══════════════════════════════════════════════╣\n");
        }
        if (start_port == end_port) {
            char ports_range[20];
            sprintf(ports_range, "%d", start_port);
            printf("    ║  Port:  %-34s   ║\n", ports_range);
        } else {
            char ports_range[20];
            sprintf(ports_range, "%d-%d", start_port, end_port);
            printf("    ║  Ports:  %-34s  ║\n", ports_range);
        }
    }
    printf("    ╠══════════════════════════════════════════════╣\n");
    printf("    ║  Scan type: %-29s    ║\n", 
           scan_type == SCAN_TCP_CONNECT ? "TCP Connect" :
           scan_type == SCAN_TCP_SYN ? "TCP SYN" : "UDP");
    printf("    ║  Timeout: %-31d ms ║\n", scan_timeout_ms);
    printf("    ╠══════════════════════════════════════════════╣\n");
    printf("    ║                                              ║\n");
    printf("    ║  1. Specify the IP address                   ║\n");
    printf("    ║  2. Specify the range of ports               ║\n");
    printf("    ║  3. Select the scan type                     ║\n");
    printf("    ║  4. Set timeout                              ║\n");
    printf("    ║  5. Start scanning                           ║\n");
    printf("    ║  6. About the program                        ║\n");
    printf("    ║  0. Exit                                     ║\n");
    printf("    ║                                              ║\n");
    printf("    ╚══════════════════════════════════════════════╝\n");
    printf("\n     Select an action: ");
}

void handle_choice(int choice) {
    switch (choice) {
        case 1: {
            clear_screen();
            printf("    ╔══════════════════════════════════════════════╗\n");
            printf("    ║             ENTERING AN IP ADDRESS           ║\n");
            printf("    ╚══════════════════════════════════════════════╝\n\n");
            printf("     Enter the IP address: ");
            if (scanf("%15s", ip) != 1 || !is_valid_ip(ip)) {
                printf("\n     Error: invalid IP address!\n");
                ip[0] = '\0';
            } else {
                printf("\n     The IP address has been successfully installed!\n");
            }   
            printf("\n     Press any key to continue...");
            _getch();
            break;
        }
        case 2: {
            clear_screen();
            printf("    ╔══════════════════════════════════════════════╗\n");
            printf("    ║           ENTERING A RANGE OF PORTS          ║\n");
            printf("    ╚══════════════════════════════════════════════╝\n\n");   
            printf("     Enter the initial port (1-65535): ");
            if (scanf("%d", &start_port) != 1) start_port = -1;  
            printf("     Enter the destination port (1-65535): ");
            if (scanf("%d", &end_port) != 1) end_port = -1;
            if (start_port < 1 || end_port > MAX_PORT || start_port > end_port){
                printf("\n     Error: Incorrect port range!\n");
                start_port = end_port = -1;
            } else {
                printf("\n     The port range has been successfully installed!\n");
            }
            printf("\n     Press any key to continue...");
            _getch();
            break;
        }
        case 3:
            set_scan_type();
            break;
        case 4:
            set_scan_timeout();
            break;
        case 5:
            scan_ports();
            break;
        case 6: {
            clear_screen();
            printf("    ╔══════════════════════════════════════════════╗\n");
            printf("    ║                    ABOUT                     ║\n");
            printf("    ╠══════════════════════════════════════════════╣\n");
            printf("    ║                                              ║\n");
            printf("    ║  Name: Port Scanner                          ║\n");
            printf("    ║  Version: 1.0                                ║\n");
            printf("    ║  Author: rbknkt                              ║\n");
            printf("    ║                                              ║\n");
            printf("    ║  https://github.com/rbknkt/PortScanner       ║\n");
            printf("    ║                                              ║\n");
            printf("    ║  Supported scanning methods:                 ║\n");
            printf("    ║  - TCP Connect                               ║\n");
            printf("    ║  - TCP SYN                                   ║\n");
            printf("    ║  - UDP                                       ║\n");
            printf("    ║                                              ║\n");
            printf("    ╚══════════════════════════════════════════════╝\n");
            printf("\n     Press any key to return to the menu...");
            _getch();
            break;
        }
        case 0: {
            exit(0);
            break;
        }   
        default: {
            printf("\n    Error: incorrect menu item!\n");
            printf("\n    Press any key to continue...");
            _getch();
            break;
        }
    }
}

int main() {
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001); 
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WinSock initialization error!\n");
        return 1;
    }
    int choice;
    while (1) {
        show_menu();  
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            choice = -1;
        }  
        handle_choice(choice);
    }
    WSACleanup();
    return 0;
}