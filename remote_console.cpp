#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT "8088"
#define BUFFER_SIZE 1024

// Structure for thread data
typedef struct {
    HANDLE pipe;
    SOCKET socket;
} THREAD_DATA;

// Function prototypes
void RunServer();
void RunClient();
DWORD WINAPI PipeToSocket(LPVOID lpParam);
DWORD WINAPI SocketToPipe(LPVOID lpParam);
void CreateChildProcess(HANDLE hChildStd_IN_Rd, HANDLE hChildStd_OUT_Wr);

// Add timestamp to log messages
void log_message(const char* format, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    printf("[%02d:%02d:%02d.%03d] ", 
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s [-c|-s]\n", argv[0]);
        return 1;
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    if (strcmp(argv[1], "-s") == 0) {
        RunServer();
    }
    else if (strcmp(argv[1], "-c") == 0) {
        RunClient();
    }
    else {
        printf("Invalid option. Use -c for client or -s for server\n");
    }

    WSACleanup();
    return 0;
}

void RunServer() {
    log_message("Server starting...");
    
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Create pipes for child process
    log_message("Creating pipes for child process...");
    HANDLE hChildStd_IN_Rd = NULL;
    HANDLE hChildStd_IN_Wr = NULL;
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;
    
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create pipes
    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0) ||
        !CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0)) {
        log_message("ERROR: CreatePipe failed");
        return;
    }
    log_message("Pipes created successfully");

    // Create child process
    log_message("Creating child process (cmd.exe)...");
    CreateChildProcess(hChildStd_IN_Rd, hChildStd_OUT_Wr);

    // Setup socket
    log_message("Setting up server socket...");
    if (getaddrinfo(NULL, DEFAULT_PORT, &hints, &result) != 0) {
        log_message("ERROR: getaddrinfo failed");
        return;
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        log_message("Error creating socket\n");
        freeaddrinfo(result);
        return;
    }

    if (bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        log_message("Bind failed\n");
        closesocket(ListenSocket);
        freeaddrinfo(result);
        return;
    }

    freeaddrinfo(result);

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        log_message("Listen failed\n");
        closesocket(ListenSocket);
        return;
    }

    log_message("Server listening on port %s", DEFAULT_PORT);
    
    // Accept client connection
    log_message("Waiting for client connection...");
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        log_message("ERROR: Accept failed");
        closesocket(ListenSocket);
        return;
    }
    log_message("Client connected");

    // Create threads for pipe-socket communication
    log_message("Creating communication threads...");
    THREAD_DATA tdPipeToSocket = { hChildStd_OUT_Rd, ClientSocket };
    THREAD_DATA tdSocketToPipe = { hChildStd_IN_Wr, ClientSocket };

    HANDLE hThreadPipeToSocket = CreateThread(NULL, 0, PipeToSocket, &tdPipeToSocket, 0, NULL);
    HANDLE hThreadSocketToPipe = CreateThread(NULL, 0, SocketToPipe, &tdSocketToPipe, 0, NULL);
    log_message("Communication threads created");

    // Wait for threads to finish
    WaitForSingleObject(hThreadPipeToSocket, INFINITE);
    WaitForSingleObject(hThreadSocketToPipe, INFINITE);

    // Cleanup
    CloseHandle(hChildStd_IN_Rd);
    CloseHandle(hChildStd_IN_Wr);
    CloseHandle(hChildStd_OUT_Rd);
    CloseHandle(hChildStd_OUT_Wr);
    closesocket(ClientSocket);
    closesocket(ListenSocket);
}

void RunClient() {
    log_message("Client starting...");
    
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, hints;
    char buffer[BUFFER_SIZE];
    int key;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result) != 0) {
        log_message("getaddrinfo failed\n");
        return;
    }

    ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        log_message("Error creating socket\n");
        freeaddrinfo(result);
        return;
    }

    log_message("Connecting to server at 127.0.0.1:%s", DEFAULT_PORT);
    if (connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        log_message("ERROR: Unable to connect to server");
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
        freeaddrinfo(result);
        return;
    }
    log_message("Connected to server successfully");

    freeaddrinfo(result);

    // Set socket to non-blocking mode
    u_long mode = 1;
    ioctlsocket(ConnectSocket, FIONBIO, &mode);

    log_message("Starting input loop. Press Ctrl+C to exit.");
    
    // Handle keyboard input and socket communication
    while (1) {
        if (_kbhit()) {
            key = _getch();
            
            // Handle special keys if needed
            if (key == 0 || key == 224) {
                key = _getch(); // Get the second byte of special keys
                continue;
            }
            
            // Echo the character locally
            if (isprint(key) || key == '\r' || key == '\n' || key == '\b') {
                printf("%c", key);
                if (key == '\r') printf("\n");
            }
            
            // Send the key to server
            if (send(ConnectSocket, (char*)&key, 1, 0) == SOCKET_ERROR) {
                if (WSAGetLastError() != WSAEWOULDBLOCK) {
                    log_message("ERROR: Failed to send data");
                    break;
                }
            }
        }

        // Check for server response with non-blocking recv
        int bytesReceived = recv(ConnectSocket, buffer, BUFFER_SIZE - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            printf("%s", buffer);
        } else if (bytesReceived == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                log_message("ERROR: Connection closed");
                break;
            }
        }

        // Small sleep to prevent CPU overload
        Sleep(10);
    }

    log_message("Client shutting down");
    closesocket(ConnectSocket);
}

DWORD WINAPI PipeToSocket(LPVOID lpParam) {
    log_message("PipeToSocket thread started");
    THREAD_DATA* pData = (THREAD_DATA*)lpParam;
    char buffer[BUFFER_SIZE];
    DWORD dwRead;
    DWORD totalBytes = 0;

    while (ReadFile(pData->pipe, buffer, BUFFER_SIZE, &dwRead, NULL)) {
        if (dwRead > 0) {
            send(pData->socket, buffer, dwRead, 0);
            totalBytes += dwRead;
            log_message("Sent %d bytes from pipe to socket (total: %d)", dwRead, totalBytes);
        }
    }
    log_message("PipeToSocket thread ending");
    return 0;
}

DWORD WINAPI SocketToPipe(LPVOID lpParam) {
    log_message("SocketToPipe thread started");
    THREAD_DATA* pData = (THREAD_DATA*)lpParam;
    char buffer[BUFFER_SIZE];
    int bytesReceived;
    DWORD dwWritten;
    DWORD totalBytes = 0;

    while ((bytesReceived = recv(pData->socket, buffer, BUFFER_SIZE, 0)) > 0) {
        WriteFile(pData->pipe, buffer, bytesReceived, &dwWritten, NULL);
        totalBytes += bytesReceived;
        log_message("Wrote %d bytes from socket to pipe (total: %d)", bytesReceived, totalBytes);
    }
    log_message("SocketToPipe thread ending");
    return 0;
}

void CreateChildProcess(HANDLE hChildStd_IN_Rd, HANDLE hChildStd_OUT_Wr) {
    log_message("Creating child process...");
    
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    siStartInfo.hStdInput = hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    if (!CreateProcess(NULL,
        "cmd.exe",
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &siStartInfo,
        &piProcInfo)) {
        log_message("ERROR: CreateProcess failed (%d)", GetLastError());
        return;
    }
    log_message("Child process created successfully (PID: %d)", piProcInfo.dwProcessId);

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
} 