#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#define APP_NAME L"shellcode"
#define APP_VERSION L"0.1"

struct _config
{
	BOOL readOnly;
	BOOL pauseBeforeExecuting;
} config = {0};

void *
LoadFileInMemory(_TCHAR *filename, DWORD *dwFileSize, DWORD flNewProtect)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	void *pBuffer = NULL;

	hFile = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"[-] CreateFile(`%s`) failed: %d.\n", filename, GetLastError());
		return NULL;
	}

	*dwFileSize = GetFileSize(hFile, NULL);
	if (*dwFileSize == INVALID_FILE_SIZE)
	{
		wprintf(L"[-] GetFileSize() failed: %d.\n", GetLastError());
		goto cleanup;
	}

	pBuffer = VirtualAlloc(NULL, *dwFileSize, MEM_COMMIT, flNewProtect);
	if (pBuffer == NULL)
	{
		wprintf(L"[-] VirtualAlloc() failed: %d.\n", GetLastError());
		goto cleanup;
	}

	if (ReadFile(hFile, pBuffer, *dwFileSize, dwFileSize, 0) == FALSE)
	{
		wprintf(L"[-] ReadFile() failed: %d.\n", GetLastError());
		VirtualFree(pBuffer, *dwFileSize, MEM_RELEASE);
		pBuffer = NULL;
		goto cleanup;
	}

cleanup:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	return pBuffer;
}


DWORD
ExecuteShellcode(_TCHAR *filename)
{
	DWORD dwFileSize = 0;
	DWORD dwRet = 0;
	void *pShellcode = NULL;

	pShellcode = LoadFileInMemory(filename, &dwFileSize, PAGE_EXECUTE_READWRITE);
	if (pShellcode == NULL)
		return 0;

	wprintf(L"[+] Shellcode address: 0x%p.\n", pShellcode);
	wprintf(L"[+] Shellcode size: %d (0x%x).\n", dwFileSize, dwFileSize);

	if (config.pauseBeforeExecuting == TRUE)
	{
		wprintf(L"[+] Press return to execute the shellcode.\n"); 
		getchar();
	}

	if (config.readOnly == TRUE)
	{
		wprintf(L"[+] Changing shellcode memory page access rights to execute only.\n");
		VirtualProtect(pShellcode, dwRet, PAGE_EXECUTE, &dwFileSize);
	}

	wprintf(L"[+] Executing shellcode.\n");

    if (config.pauseBeforeExecuting == TRUE)
        DebugBreak();

	((void(*)())pShellcode)();

	wprintf(L"[+] Done.\n");

	if (pShellcode != NULL)
		VirtualFree(pShellcode, dwFileSize, MEM_RELEASE);

	return 1;
}

/***************************************************************************/
/* Main.                                                                   */
/***************************************************************************/

void
Usage(_TCHAR *argv)
{
	wprintf(L"Usage: %s [options] shellcode.bin\n", argv);
	wprintf(L"  -p                Pause before executing shellcode.\n");
	wprintf(L"  -w                Shellcode page is rwx.\n");
	wprintf(L"  -f                Load a file in memory.\n");
	exit(255);
}

int 
_tmain(int argc, _TCHAR *argv[]) 
{
	int i = 0;

	wprintf(L"-=[ %s %s ]=-\n\n", APP_NAME, APP_VERSION);
	wprintf(L"[+] Current PID: %x (%d)\n\n", GetCurrentProcessId(), 
		                                     GetCurrentProcessId());

	if (argc < 2)
	    Usage(argv[0]);

	config.readOnly = TRUE;
	config.pauseBeforeExecuting = FALSE;

	/* Argugment parsing. */
	for (i = 1 ; i < argc ; i++)
	{
		if (!wcscmp(argv[i], L"-p"))
		{
			config.pauseBeforeExecuting = TRUE;
		}
		else if (!wcscmp(argv[i], L"-w"))
			config.readOnly = FALSE;
		else if (!wcscmp(argv[i], L"-f"))
		{
			DWORD dwSize = 0;
			if (++i >= argc)
				Usage(argv[0]);
			if (LoadFileInMemory(argv[i], &dwSize, PAGE_READWRITE) == NULL)
				Usage(argv[0]);
		}
		else if (!wcscmp(argv[i], L"-h"))
			Usage(argv[0]);
		else
			break;
	}

	return ExecuteShellcode(argv[i]);
}