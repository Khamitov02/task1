#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT "8088"
#define BUFFER_SIZE 1024
#define CMD_EXE "cmd.exe"

// Structure for thread data
typedef struct {
    HANDLE pipe;
    SOCKET socket;
} THREAD_DATA;

// Add new structure to hold client information
typedef struct {
    SOCKET socket;
    HANDLE hChildStd_IN_Rd;
    HANDLE hChildStd_IN_Wr;
    HANDLE hChildStd_OUT_Rd;
    HANDLE hChildStd_OUT_Wr;
    PROCESS_INFORMATION piProcInfo;
} CLIENT_DATA;

// Function prototypes
void RunServer();
void RunClient();
DWORD WINAPI PipeToSocket(LPVOID lpParam);
DWORD WINAPI SocketToPipe(LPVOID lpParam);
void CreateChildProcess(HANDLE hChildStd_IN_Rd, HANDLE hChildStd_OUT_Wr);
DWORD WINAPI HandleClient(LPVOID lpParam);

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
    struct addrinfo *result = NULL, hints;
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Setup socket
    log_message("Setting up server socket...");
    if (getaddrinfo(NULL, DEFAULT_PORT, &hints, &result) != 0) {
        log_message("ERROR: getaddrinfo failed");
        return;
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        log_message("Error creating socket");
        freeaddrinfo(result);
        return;
    }

    if (bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        log_message("Bind failed");
        closesocket(ListenSocket);
        freeaddrinfo(result);
        return;
    }

    freeaddrinfo(result);

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        log_message("Listen failed");
        closesocket(ListenSocket);
        return;
    }

    log_message("Server listening on port %s", DEFAULT_PORT);

    // Main server loop
    while(1) {
        log_message("Waiting for client connection...");
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            log_message("ERROR: Accept failed");
            continue;
        }

        // Create new client data structure
        CLIENT_DATA* clientData = (CLIENT_DATA*)malloc(sizeof(CLIENT_DATA));
        if (clientData == NULL) {
            log_message("ERROR: Failed to allocate client data");
            closesocket(ClientSocket);
            continue;
        }
        clientData->socket = ClientSocket;

        // Create thread to handle this client
        HANDLE hThread = CreateThread(NULL, 0, HandleClient, clientData, 0, NULL);
        if (hThread == NULL) {
            log_message("ERROR: Failed to create client thread");
            free(clientData);
            closesocket(ClientSocket);
            continue;
        }
        CloseHandle(hThread); // Thread will run independently
        
        log_message("New client connected and handler thread created");
    }

    closesocket(ListenSocket);
}

DWORD WINAPI HandleClient(LPVOID lpParam) {
    CLIENT_DATA* clientData = (CLIENT_DATA*)lpParam;
    HANDLE hThreadPipeToSocket = NULL;
    HANDLE hThreadSocketToPipe = NULL;
    THREAD_DATA tdPipeToSocket;
    THREAD_DATA tdSocketToPipe;
    STARTUPINFO siStartInfo;
    BOOL success = FALSE;

    log_message("Starting handler for new client connection");

    // Create pipes for child process
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    log_message("Creating pipes for child process...");
    if (!CreatePipe(&clientData->hChildStd_OUT_Rd, &clientData->hChildStd_OUT_Wr, &saAttr, 0) ||
        !CreatePipe(&clientData->hChildStd_IN_Rd, &clientData->hChildStd_IN_Wr, &saAttr, 0)) {
        log_message("ERROR: CreatePipe failed");
        goto CLEANUP;
    }
    log_message("Pipes created successfully");

    // Create child process
    log_message("Creating child process (cmd.exe)...");
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = clientData->hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = clientData->hChildStd_OUT_Wr;
    siStartInfo.hStdInput = clientData->hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create process with proper string handling
    if (!CreateProcess(NULL,
        (LPSTR)CMD_EXE,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &siStartInfo,
        &clientData->piProcInfo)) {
        log_message("ERROR: CreateProcess failed (%d)", GetLastError());
        goto CLEANUP;
    }
    log_message("Child process created successfully (PID: %d)", clientData->piProcInfo.dwProcessId);

    // Initialize thread data
    tdPipeToSocket.pipe = clientData->hChildStd_OUT_Rd;
    tdPipeToSocket.socket = clientData->socket;
    tdSocketToPipe.pipe = clientData->hChildStd_IN_Wr;
    tdSocketToPipe.socket = clientData->socket;

    // Create communication threads
    hThreadPipeToSocket = CreateThread(NULL, 0, PipeToSocket, &tdPipeToSocket, 0, NULL);
    if (hThreadPipeToSocket == NULL) {
        log_message("ERROR: Failed to create PipeToSocket thread");
        goto CLEANUP;
    }

    hThreadSocketToPipe = CreateThread(NULL, 0, SocketToPipe, &tdSocketToPipe, 0, NULL);
    if (hThreadSocketToPipe == NULL) {
        log_message("ERROR: Failed to create SocketToPipe thread");
        goto CLEANUP;
    }

    log_message("Communication threads created successfully");
    
    // Wait for both threads
    WaitForSingleObject(hThreadPipeToSocket, INFINITE);
    WaitForSingleObject(hThreadSocketToPipe, INFINITE);
    success = TRUE;

CLEANUP:
    log_message("Cleaning up client connection...");
    
    // Close thread handles if they were created
    if (hThreadPipeToSocket) CloseHandle(hThreadPipeToSocket);
    if (hThreadSocketToPipe) CloseHandle(hThreadSocketToPipe);

    // Terminate the child process if it's still running
    if (clientData->piProcInfo.hProcess) {
        TerminateProcess(clientData->piProcInfo.hProcess, 0);
        CloseHandle(clientData->piProcInfo.hProcess);
        CloseHandle(clientData->piProcInfo.hThread);
    }

    // Close handles and socket
    if (clientData->hChildStd_IN_Rd) CloseHandle(clientData->hChildStd_IN_Rd);
    if (clientData->hChildStd_IN_Wr) CloseHandle(clientData->hChildStd_IN_Wr);
    if (clientData->hChildStd_OUT_Rd) CloseHandle(clientData->hChildStd_OUT_Rd);
    if (clientData->hChildStd_OUT_Wr) CloseHandle(clientData->hChildStd_OUT_Wr);
    if (clientData->socket != INVALID_SOCKET) closesocket(clientData->socket);
    
    free(clientData);
    log_message("Client handler thread ending");
    return success ? 0 : 1;
}

void RunClient() {
    log_message("Client starting...");
    
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, hints;
    char buffer[BUFFER_SIZE];
    char inputBuffer[BUFFER_SIZE] = {0};
    int inputPos = 0;
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

    log_message("Starting SSH-like console. Press Ctrl+C to exit.");
    printf("Remote console ready. Type commands and press Enter.\n");
    
    while (1) {
        if (_kbhit()) {
            key = _getch();
            
            // Handle special keys
            if (key == 0 || key == 224) {
                key = _getch(); // Get the second byte of special keys
                continue;
            }
            
            // Handle backspace
            if (key == '\b' && inputPos > 0) {
                printf("\b \b");  // Erase character from screen
                inputPos--;
                inputBuffer[inputPos] = 0;
                continue;
            }
            
            // Handle enter key
            if (key == '\r') {
                inputBuffer[inputPos] = '\n';
                inputPos++;
                printf("\n");
                
                // Send the complete command
                if (send(ConnectSocket, inputBuffer, inputPos, 0) == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSAEWOULDBLOCK) {
                        log_message("ERROR: Failed to send command");
                        break;
                    }
                }
                
                // Reset input buffer
                memset(inputBuffer, 0, BUFFER_SIZE);
                inputPos = 0;
                continue;
            }
            
            // Handle regular characters
            if (inputPos < BUFFER_SIZE - 2 && isprint(key)) {
                inputBuffer[inputPos++] = key;
                printf("%c", key);  // Echo character
            }
        }

        // Check for server response
        int bytesReceived = recv(ConnectSocket, buffer, BUFFER_SIZE - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            printf("%s", buffer);
            fflush(stdout);
        } else if (bytesReceived == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                log_message("ERROR: Connection closed");
                break;
            }
        }

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

    while (ReadFile(pData->pipe, buffer, BUFFER_SIZE - 1, &dwRead, NULL)) {
        if (dwRead > 0) {
            buffer[dwRead] = '\0';  // Ensure null termination
            
            int bytesSent = 0;
            while (bytesSent < dwRead) {
                int result = send(pData->socket, buffer + bytesSent, dwRead - bytesSent, 0);
                if (result == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSAEWOULDBLOCK) {
                        log_message("ERROR: Failed to send data to socket");
                        return 1;
                    }
                    Sleep(10);  // Wait a bit if would block
                    continue;
                }
                bytesSent += result;
            }
            
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

    while ((bytesReceived = recv(pData->socket, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        // Ensure command ends with newline
        if (buffer[bytesReceived-1] != '\n') {
            buffer[bytesReceived] = '\n';
            bytesReceived++;
        }
        
        if (!WriteFile(pData->pipe, buffer, bytesReceived, &dwWritten, NULL)) {
            log_message("ERROR: Failed to write to pipe");
            break;
        }
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
        (LPSTR)CMD_EXE,
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