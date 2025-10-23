/*
Tool: TcpSnooper
File: TcpSnooper.cpp
Author: Ayi NEDJIMI Consultants
URL: https://www.ayinedjimi-consultants.fr
Version: 1.0
Description:
  Liste toutes les connexions TCP et UDP actives sur la machine locale, associe chaque
  connexion à son processus (PID et nom), et permet le rafraîchissement en temps réel.
  Utile pour détecter des connexions suspectes ou non autorisées.
Prerequisites:
  - Windows 10 / Windows Server 2016+ (x64)
  - Visual Studio Developer Command Prompt (x64)
  - Droits normaux suffisants (élévation pour certains processus système)
Notes:
  - Outil en mode audit par défaut. Voir section LAB-CONTROLLED dans README pour démonstration en VM isolée.

WinToolsSuite – Security Tools for Network & Pentest
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training
*/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <mutex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "comctl32.lib")

// Messages
#define WM_TOOL_RESULT   (WM_APP + 200)
#define WM_TOOL_ERROR    (WM_APP + 201)

// Contrôles
#define IDC_LISTVIEW     1001
#define IDC_BTN_REFRESH  1002
#define IDC_BTN_EXPORT   1003
#define IDC_BTN_AUTO     1004
#define ID_FILE_EXPORT   2001
#define ID_FILE_EXIT     2002
#define ID_HELP_ABOUT    2003

// RAII Handle
class AutoHandle {
    HANDLE h;
public:
    explicit AutoHandle(HANDLE handle = INVALID_HANDLE_VALUE) : h(handle) {}
    ~AutoHandle() { if (h != INVALID_HANDLE_VALUE && h != NULL) CloseHandle(h); }
    operator HANDLE() const { return h; }
};

struct ConnectionInfo {
    std::wstring protocol;
    std::wstring localAddr;
    std::wstring remoteAddr;
    std::wstring state;
    DWORD pid;
    std::wstring processName;
};

// Globals
HWND g_hwnd = NULL;
HWND g_hwndList = NULL;
std::vector<ConnectionInfo> g_connections;
std::mutex g_mutex;
std::wofstream g_logFile;
bool g_autoRefresh = false;
std::thread g_autoThread;

void LogMessage(const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[100];
    swprintf_s(timeBuf, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (g_logFile.is_open()) {
        g_logFile << timeBuf << msg << std::endl;
        g_logFile.flush();
    }
}

void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_TcpSnooper_log.txt";
    g_logFile.open(logPath, std::ios::app);
    LogMessage(L"=== TcpSnooper démarré ===");
}

std::wstring GetProcessName(DWORD pid) {
    if (pid == 0) return L"System Idle";
    if (pid == 4) return L"System";

    AutoHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (hProc.get() == NULL) return L"<Accès refusé>";

    wchar_t exePath[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc.get(), 0, exePath, &size)) {
        std::wstring path(exePath);
        size_t pos = path.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            return path.substr(pos + 1);
        }
        return path;
    }

    return L"<Inconnu>";
}

std::wstring StateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return L"CLOSED";
        case MIB_TCP_STATE_LISTEN: return L"LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return L"SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return L"SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return L"FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return L"FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return L"CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return L"LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
        default: return L"UNKNOWN";
    }
}

std::wstring IpToString(DWORD ip) {
    std::wstringstream wss;
    wss << (ip & 0xFF) << L"."
        << ((ip >> 8) & 0xFF) << L"."
        << ((ip >> 16) & 0xFF) << L"."
        << ((ip >> 24) & 0xFF);
    return wss.str();
}

void EnumerateTcp() {
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD size = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (pTcpTable) {
            if (GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];

                    ConnectionInfo info;
                    info.protocol = L"TCP";

                    std::wstringstream local;
                    local << IpToString(row.dwLocalAddr) << L":" << ntohs((WORD)row.dwLocalPort);
                    info.localAddr = local.str();

                    std::wstringstream remote;
                    remote << IpToString(row.dwRemoteAddr) << L":" << ntohs((WORD)row.dwRemotePort);
                    info.remoteAddr = remote.str();

                    info.state = StateToString(row.dwState);
                    info.pid = row.dwOwningPid;
                    info.processName = GetProcessName(row.dwOwningPid);

                    std::lock_guard<std::mutex> lock(g_mutex);
                    g_connections.push_back(info);
                }
            }
            free(pTcpTable);
        }
    }
}

void EnumerateUdp() {
    PMIB_UDPTABLE_OWNER_PID pUdpTable = NULL;
    DWORD size = 0;

    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (pUdpTable) {
            if (GetExtendedUdpTable(pUdpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];

                    ConnectionInfo info;
                    info.protocol = L"UDP";

                    std::wstringstream local;
                    local << IpToString(row.dwLocalAddr) << L":" << ntohs((WORD)row.dwLocalPort);
                    info.localAddr = local.str();

                    info.remoteAddr = L"*:*";
                    info.state = L"-";
                    info.pid = row.dwOwningPid;
                    info.processName = GetProcessName(row.dwOwningPid);

                    std::lock_guard<std::mutex> lock(g_mutex);
                    g_connections.push_back(info);
                }
            }
            free(pUdpTable);
        }
    }
}

void RefreshConnections() {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_connections.clear();
    }

    EnumerateTcp();
    EnumerateUdp();

    PostMessageW(g_hwnd, WM_TOOL_RESULT, 0, 0);
}

void UpdateListView() {
    ListView_DeleteAllItems(g_hwndList);

    std::lock_guard<std::mutex> lock(g_mutex);

    int index = 0;
    for (const auto& conn : g_connections) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(conn.protocol.c_str());
        ListView_InsertItem(g_hwndList, &lvi);

        ListView_SetItemText(g_hwndList, index, 1, const_cast<LPWSTR>(conn.localAddr.c_str()));
        ListView_SetItemText(g_hwndList, index, 2, const_cast<LPWSTR>(conn.remoteAddr.c_str()));
        ListView_SetItemText(g_hwndList, index, 3, const_cast<LPWSTR>(conn.state.c_str()));

        wchar_t pidBuf[32];
        swprintf_s(pidBuf, L"%lu", conn.pid);
        ListView_SetItemText(g_hwndList, index, 4, pidBuf);

        ListView_SetItemText(g_hwndList, index, 5, const_cast<LPWSTR>(conn.processName.c_str()));

        index++;
    }

    wchar_t title[256];
    swprintf_s(title, L"TcpSnooper - %d connexions", (int)g_connections.size());
    SetWindowTextW(g_hwnd, title);
}

void ExportToCsv(const std::wstring& filename) {
    std::wofstream file(filename);
    if (!file.is_open()) {
        MessageBoxW(g_hwnd, L"Impossible de créer le fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    file.put(0xFEFF); // BOM UTF-8

    file << L"Protocole,Adresse locale,Adresse distante,État,PID,Processus\n";

    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& conn : g_connections) {
        file << conn.protocol << L",";
        file << L"\"" << conn.localAddr << L"\",";
        file << L"\"" << conn.remoteAddr << L"\",";
        file << conn.state << L",";
        file << conn.pid << L",";
        file << L"\"" << conn.processName << L"\"\n";
    }

    file.close();
    MessageBoxW(g_hwnd, L"Export CSV réussi", L"Information", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Export CSV: " + filename);
}

void ShowAboutDialog() {
    MessageBoxW(g_hwnd,
        L"TcpSnooper v1.0\n\n"
        L"Liste les connexions TCP/UDP actives et leurs processus\n\n"
        L"WinToolsSuite – Security Tools for Network & Pentest\n"
        L"Developed by Ayi NEDJIMI Consultants\n"
        L"https://www.ayinedjimi-consultants.fr\n"
        L"© 2025 – Cybersecurity Research & Training",
        L"À propos",
        MB_OK | MB_ICONINFORMATION);
}

void InitListView(HWND hwndList) {
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.cx = 80;
    lvc.pszText = const_cast<LPWSTR>(L"Protocole");
    ListView_InsertColumn(hwndList, 0, &lvc);

    lvc.cx = 180;
    lvc.pszText = const_cast<LPWSTR>(L"Adresse locale");
    ListView_InsertColumn(hwndList, 1, &lvc);

    lvc.cx = 180;
    lvc.pszText = const_cast<LPWSTR>(L"Adresse distante");
    ListView_InsertColumn(hwndList, 2, &lvc);

    lvc.cx = 100;
    lvc.pszText = const_cast<LPWSTR>(L"État");
    ListView_InsertColumn(hwndList, 3, &lvc);

    lvc.cx = 80;
    lvc.pszText = const_cast<LPWSTR>(L"PID");
    ListView_InsertColumn(hwndList, 4, &lvc);

    lvc.cx = 200;
    lvc.pszText = const_cast<LPWSTR>(L"Processus");
    ListView_InsertColumn(hwndList, 5, &lvc);

    ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

void AutoRefreshThread() {
    while (g_autoRefresh) {
        RefreshConnections();
        Sleep(2000);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreateMenu();
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXPORT, L"&Exporter CSV...");
            AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT, L"&Quitter");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&Fichier");

            HMENU hHelpMenu = CreateMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_HELP_ABOUT, L"&À propos...");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Aide");
            SetMenu(hwnd, hMenu);

            g_hwndList = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT,
                10, 10, 980, 450,
                hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);
            InitListView(g_hwndList);

            CreateWindowExW(0, L"BUTTON", L"Rafraîchir",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 470, 150, 30,
                hwnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 470, 150, 30,
                hwnd, (HMENU)IDC_BTN_EXPORT, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Auto-rafraîchir",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                330, 470, 150, 30,
                hwnd, (HMENU)IDC_BTN_AUTO, GetModuleHandle(NULL), NULL);

            RefreshConnections();
            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case IDC_BTN_REFRESH:
                    RefreshConnections();
                    LogMessage(L"Rafraîchissement manuel");
                    break;

                case IDC_BTN_EXPORT:
                case ID_FILE_EXPORT: {
                    wchar_t filename[MAX_PATH] = L"connections.csv";
                    OPENFILENAMEW ofn = {};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFile = filename;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
                    ofn.Flags = OFN_OVERWRITEPROMPT;
                    if (GetSaveFileNameW(&ofn)) {
                        ExportToCsv(filename);
                    }
                    break;
                }

                case IDC_BTN_AUTO:
                    if (SendMessageW(GetDlgItem(hwnd, IDC_BTN_AUTO), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        g_autoRefresh = true;
                        g_autoThread = std::thread(AutoRefreshThread);
                        LogMessage(L"Auto-rafraîchissement activé");
                    } else {
                        g_autoRefresh = false;
                        if (g_autoThread.joinable()) g_autoThread.join();
                        LogMessage(L"Auto-rafraîchissement désactivé");
                    }
                    break;

                case ID_FILE_EXIT:
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    break;

                case ID_HELP_ABOUT:
                    ShowAboutDialog();
                    break;
            }
            break;
        }

        case WM_TOOL_RESULT:
            UpdateListView();
            break;

        case WM_DESTROY:
            g_autoRefresh = false;
            if (g_autoThread.joinable()) g_autoThread.join();
            if (g_logFile.is_open()) {
                LogMessage(L"=== TcpSnooper arrêté ===");
                g_logFile.close();
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    InitLog();

    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"TcpSnooper";

    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, L"TcpSnooper",
        L"TcpSnooper - Connexions actives",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1020, 570,
        NULL, NULL, hInstance, NULL);

    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
