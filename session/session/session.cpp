#include <iostream>
#include <Cstring>
#include <windows.h>
#include <Wtsapi32.h>
#include <iphlpapi.h>
#include <WinBase.h>
#include <Tchar.h>
#include <Psapi.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib,"Psapi.lib")

using namespace std;

bool GetSessionDomain(DWORD dwSessionId, char domain[256]) 
{
	LPTSTR		pBuffer = NULL; 
	DWORD		dwBufferLen; 

	BOOL bRet = WTSQuerySessionInformation(
									WTS_CURRENT_SERVER_HANDLE, 
									dwSessionId, 
									WTSDomainName, 
									&pBuffer, 
									&dwBufferLen);
	 if ( !bRet )
	 {
		printf("WTSQuerySessionInformation Failed!/n");
		return false;
	 }

	 lstrcpy(domain,pBuffer); 
	 WTSFreeMemory(pBuffer); 

	 return true;
}

bool GetSessionUserName(DWORD dwSessionId, char username[256])
{
	LPTSTR		pBuffer	= NULL; 
	DWORD		dwBufferLen; 
	
	BOOL		bRet = WTSQuerySessionInformation(
										WTS_CURRENT_SERVER_HANDLE, 
										dwSessionId, 
										WTSUserName, 
										&pBuffer, 
										&dwBufferLen); 
	if ( !bRet )
	{
		printf("GetSessionUserName Failed!/n");
		return false;
	}

	lstrcpy(username ,pBuffer); 
	WTSFreeMemory(pBuffer);

	return true;
}

/* ��������session id ���� */
int EnmumSessionId()
{
	WTS_SESSION_INFO	*sessionInfo = NULL; 
	DWORD				sessionInfoCount;
	char				domain[256]; 
	char				username[256];
	unsigned int		userCount = 0;
	int					num=0; 
	
	BOOL bRet = WTSEnumerateSessions(
								WTS_CURRENT_SERVER_HANDLE, 
								0, 
								1, 
								&sessionInfo, 
								&sessionInfoCount); 
	if ( !bRet )
	{
		return false;
	}
	
	for (int i = 0; i < sessionInfoCount;++i)
	{
		 if( (sessionInfo[i].State == WTSActive) || 
				(sessionInfo[i].State == WTSDisconnected) )
		 {
			 printf("session %d information:\n",num++); 
			 printf("\tsessionInfo.SessionId=%d\n",sessionInfo[i].SessionId); 
			 GetSessionDomain(sessionInfo[i].SessionId, domain); //���Session Domain
			 printf("\tSession Domain = %s\n",domain);
			 GetSessionUserName(sessionInfo[i].SessionId,username);
			 printf("\tSession username = %s\n",username); 
		 }
	}

	// ��ȡ��ǰsessionid
	DWORD dwSession = WTSGetActiveConsoleSessionId();
	printf("[*] Current Active SessionId = %d\n",dwSession); 

	// �ͷ��ڴ�
	WTSFreeMemory(sessionInfo);

	return 0;
}

/* ����Ȩ�޺��� */  
BOOL EnableProcessPrivilege(LPCTSTR lpszPrivName, BOOL bEnable = TRUE)
{
        HANDLE hToken; 
        TOKEN_PRIVILEGES tkp;
        BOOL bRet = FALSE;

        bRet = OpenProcessToken(
						GetCurrentProcess(), 
						TOKEN_ALL_ACCESS_P, 
						&hToken);

        if (bRet == FALSE)
        {
                printf("OpenProcessToken error\r\n");
        }

        bRet = LookupPrivilegeValue(
								NULL, 
								lpszPrivName, 
								&tkp.Privileges[0].Luid); //�޸Ľ���Ȩ��
        tkp.PrivilegeCount = 1;  
        tkp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED; 

        bRet = AdjustTokenPrivileges(
								hToken, 
								FALSE, 
								&tkp, 
								0, 
								(PTOKEN_PRIVILEGES)NULL, 
								0); //֪ͨϵͳ�޸Ľ���Ȩ�� 
        bRet = TRUE;

        CloseHandle(hToken);
        return bRet;
}


int main( int argc,char **argv )
{
	HANDLE	hTokenDup = NULL;
	DWORD dwSessionId = 0;
	HANDLE	hToken = NULL;
	HANDLE hNewToken = NULL;	
	DWORD dwProcessId = atoi(argv[1]); 

	/* ������ǰ����Ȩ�� */
	if ( !EnableProcessPrivilege(SE_DEBUG_NAME, TRUE) )   //SE_DEBUG_NAME
	{
		printf("[*]:EnableProcessPrivilege failed\n");
		return false;
	}

	/* ͨ��pid�򿪽��� */
	HANDLE hProcess = OpenProcess(
							PROCESS_QUERY_INFORMATION , 
							FALSE, 
							dwProcessId); // �õ����̾��
	if ( NULL == hProcess )
	{
		printf("[-]:OpenProcess GetLastError : %d\n",GetLastError());
		CloseHandle(hProcess);
	}

	/* ��ý������� */
	BOOL bRet = OpenProcessToken(
							hProcess, 
							TOKEN_ALL_ACCESS, 
							&hToken); // �򿪽�������
	if ( FALSE == bRet )
	{
		printf("[-]:OpenProcessToken GetLastError : %d\n",GetLastError());
		CloseHandle(hToken);
		CloseHandle(hProcess);
	}

	/* ͨ��pid��ȡ�û�session id*/

	DWORD dwLength = 0;
	DWORD tsi = 0;

	if (!GetTokenInformation(
						hToken,         // handle to the access token
						TokenSessionId,    // get information about the TokenSessionId
						&tsi,   // pointer to TokenSessionId buffer
						0,              // size of buffer
						&dwLength       // receives required buffer size
      )) 
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			return false;
		}
    }

	if (!GetTokenInformation(
						hToken,         // handle to the access token
						TokenSessionId,    // get information about the TokenSessionId
						&tsi,   // pointer to TokenSessionId buffer
						dwLength,       // size of buffer
						&dwLength       // receives required buffer size
         )) 
    {
      return false;
    }

	printf("[*]:Patch sessionId = %d\n",tsi);
	printf("[*]:Patch processId = %d\n",dwProcessId);
	printf("[*]:Enable Process Privilege successful\n");
	
	/* ����һ���������ƣ�Ŀ����Ϊ���޸�session id���ԣ��Ա�������session�д������� */
	BOOL bRes = DuplicateTokenEx(
							hToken,
							MAXIMUM_ALLOWED,
							NULL,
							SecurityIdentification,
							TokenPrimary,
							&hTokenDup);  
	if ( !bRes )
	{
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
	}
		
	if (!ImpersonateLoggedOnUser(hTokenDup))
	{
		printf("[-]:ImpersonateLoggedOnUser GetLastError: %d\n",GetLastError());
		CloseHandle(hTokenDup);
	}

	/* ��session id���õ����ݵ������� 
	BOOL bsRet = SetTokenInformation(
								hTokenDup, 
								TokenSessionId, 
								&tsi,				//&dwSessionId, 
								sizeof(DWORD)); 
	
	if ( !bsRet )
	{
		printf("[-]:SetTokenInformation GetLastError: %d\n",GetLastError());
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
	}
	*/
	/* ��������*/
	STARTUPINFO   si = {0};
	PROCESS_INFORMATION   pi = {0};
	char path[MAX_PATH]; 
	lstrcpy(path,argv[2]);  //����2 

	ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	BOOL status =  CreateProcessAsUser(
							hTokenDup,            // client's access token
							NULL,   // file to execute
							(char *)path,     // command line
							NULL,              // pointer to process SECURITY_ATTRIBUTES
							NULL,              // pointer to thread SECURITY_ATTRIBUTES
							FALSE,             // handles are not inheritable
							NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT ,   // creation flags
							NULL,              // pointer to new environment block 
							NULL,              // name of current directory 
							&si,               // pointer to STARTUPINFO structure
							&pi                // receives information about new process
							); 
	if ( !status )
	{
		printf("[-]:CreateProcessAsUser GetLastError:%d\n",GetLastError());
		RevertToSelf();
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
		WTSFreeMemory(&si);
		WTSFreeMemory(&pi);
		ExitProcess(0);
	}
	printf("[*]:CreateProcess successful\n");
	RevertToSelf();
	CloseHandle(hTokenDup);
	CloseHandle(hToken);
	WTSFreeMemory(&si);
	WTSFreeMemory(&pi);
	ExitProcess(0);

	return 0;
}