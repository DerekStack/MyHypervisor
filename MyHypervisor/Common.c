#include <ntddk.h>
#include <wdf.h>
#include "Msr.h"
#include "Common.h"
#include "Vmx.h"


/* Set Bits for a special address (used on MSR Bitmaps) */
void SetBit(PVOID Addr, UINT64 bit, BOOLEAN Set) {

	UINT64 byte;
	UINT64 temp;
	UINT64 n;
	BYTE* Addr2;

	byte = bit / 8;
	temp = bit % 8;
	n = 7 - temp;

	Addr2 = Addr;

	if (Set)
	{
		Addr2[byte] |= (1 << n);
	}
	else
	{
		Addr2[byte] &= ~(1 << n);
	}
}

/* Get Bits of a special address (used on MSR Bitmaps) */
void GetBit(PVOID Addr, UINT64 bit) {

	UINT64 byte, k;
	BYTE* Addr2;

	byte = 0;
	k = 0;
	byte = bit / 8;
	k = 7 - bit % 8;

	Addr2 = Addr;

	return Addr2[byte] & (1 << k);
}

/* Converts Virtual Address to Physical Address */
UINT64 VirtualAddressToPhysicalAddress(PVOID VirtualAddress)
{
	return MmGetPhysicalAddress(VirtualAddress).QuadPart;
}

/* Converts Physical Address to Virtual Address */
UINT64 PhysicalAddressToVirtualAddress(UINT64 PhysicalAddress)
{
	PHYSICAL_ADDRESS PhysicalAddr;
	PhysicalAddr.QuadPart = PhysicalAddress;

	return MmGetVirtualForPhysical(PhysicalAddr);
}

PFN_NUMBER PfnFromVirtualAddress(void* va)
{
	return PfnFromPhysicalAddress(VirtualAddressToPhysicalAddress(va));
}

// PA -> PFN
PFN_NUMBER PfnFromPhysicalAddress(ULONG64 pa)
{
	return (PFN_NUMBER)(pa >> PAGE_SHIFT);
}

/* Print logs in different levels */
VOID LogPrintInfo(PCSTR Format) 
{
	DbgPrint(Format);
}

VOID LogPrintWarning(PCSTR Format) 
{
	DbgPrint(Format);
}

VOID LogPrintError(PCSTR Format) 
{
	DbgPrint(Format);
}
