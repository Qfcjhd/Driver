#include <ntifs.h>


typedef struct _NON_PAGED_DEBUG_INFO {
	USHORT      Signature;
	USHORT      Flags;
	ULONG       Size;
	USHORT      Machine;
	USHORT      Characteristics;
	ULONG       TimeDateStamp;
	ULONG       CheckSum;
	ULONG       SizeOfImage;
	ULONGLONG   ImageBase;
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase; //��ַ
	PVOID EntryPoint; //��ڵ�
	ULONG SizeOfImage; //��С
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount; //�������ش���
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef VOID(*MiProcessLoaderEntryPROC)(IN PKLDR_DATA_TABLE_ENTRY DataTableEntry, IN LOGICAL Insert);

CHAR ShellCode[] = { 0x8B,0xFF,0x55,0x8B,0xEC,0x51,0x53,0x8B,0x5D,'*',0x56,0x57,0x6A,'*',0x68,'*','*','*','*',0xE8,'*','*','*','*',0xFF,0x15 };

VOID Driver_UnLoad(PDRIVER_OBJECT pDriver)
{
	KdPrint(("DriverUnLoad"));
}

/*
	IfShellCode �ж�shellcode �Ƿ����ڴ�����������
	startAddr �ڴ濪ʼ��ַ
	shellCode Ӳ����
	shellCodeLen Ӳ���볤��
*/
BOOLEAN IfShellCodeExistMemory(PULONG startAddr,PCHAR shellCode, ULONG shellCodeLen)
{
	PCHAR tempStarAddr = (PCHAR)startAddr;
	for (ULONG i = 0; i < shellCodeLen; i++)
	{
		if (shellCode[i] != '*')
		{
			if (tempStarAddr[i] == shellCode[i])
			{
				if(i == (shellCodeLen - 1))
				{
					return TRUE;
				}
			}
			else 
			{
				break;
			}
		}
	}
	return FALSE;
}

/*
	GetFunctionAddr ��ȡ������ַ
	startAddr Ҫ�����Ŀ�ʼ��ַ
	endAdder Ҫ�����Ľ�����ַ
	shellCode Ӳ����
	shellCodeLen Ӳ���볤��
*/
PULONG GetFunctionAddr(PULONG startAddr, PULONG endAdder,PCHAR shellCode, ULONG shellCodeLen)
{
	PULONG functionAddr = NULL;

	PULONG tempStartAddr = startAddr;
	PULONG tempEndAddr = endAdder;

	BOOLEAN status = FALSE;

	KdPrint(("��ʼ��ַ: %x, ������ַ: %x\r\n", tempStartAddr, tempEndAddr));

	while ((ULONG)tempStartAddr != (ULONG)tempEndAddr)
	{
		//KdPrint(("tempStartAddr: %x \r\n", tempStartAddr));

		status = IfShellCodeExistMemory(tempStartAddr, shellCode, shellCodeLen);
		if (status)
		{
			KdPrint(("%x\r\n", startAddr));
			functionAddr = tempStartAddr;
			return functionAddr;
		}
		tempStartAddr = (PULONG)((ULONG)tempStartAddr + 1);
 	}
	KdPrint(("tempStartAddr: %x \r\n", tempStartAddr));
	return functionAddr;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	KdPrint(("DriverEntry"));


	PKLDR_DATA_TABLE_ENTRY pdte_Header = &((PKLDR_DATA_TABLE_ENTRY)pDriver->DriverSection)->InLoadOrderLinks.Flink;
	PKLDR_DATA_TABLE_ENTRY pdte_NextHeader = pdte_Header->InLoadOrderLinks.Flink;

	UNICODE_STRING pBaseName = { 0 };
	RtlInitUnicodeString(&pBaseName, L"ntoskrnl.exe");

	PULONG funAddr = NULL;


	while (pdte_NextHeader != pdte_Header) 
	{
		//KdPrint(("%wZ\r\n", &pdte_NextHeader->BaseDllName));

		if (RtlCompareUnicodeString(&pBaseName, &pdte_NextHeader->BaseDllName, TRUE) == 0) 
		{
			KdPrint(("%wZ �ҵ���\r\n", &pdte_NextHeader->BaseDllName));

			KdPrint(("ShellCOdes��С: %d\r\n",sizeof(ShellCode)));

			ULONG shellCodeSize = sizeof(ShellCode);

			//ģ���С
			ULONG sizeOfImage = pdte_NextHeader->SizeOfImage;
			ULONG imageBase =  pdte_NextHeader->DllBase;

			KdPrint(("ģ���С: %x  ģ���ַ:%x\r\n", sizeOfImage,(ULONG)imageBase));
			funAddr = GetFunctionAddr((PULONG)imageBase,(PULONG)(imageBase + sizeOfImage),ShellCode, shellCodeSize);
			KdPrint(("funAddr :%x\r\n", funAddr));
			break;
		}

		pdte_NextHeader = pdte_NextHeader->InLoadOrderLinks.Flink;
	}

	MiProcessLoaderEntryPROC MiProcessLoaderEntry = funAddr;
	MiProcessLoaderEntry(pdte_Header, FALSE);


	KdPrint(("DriverMain"));

	pDriver->DriverUnload = Driver_UnLoad;
	return STATUS_SUCCESS;
}