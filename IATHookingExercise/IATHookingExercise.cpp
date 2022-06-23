#include "pch.h"


#define MAX 100
#define FILENAME "C:\\Operating Systems\\IATHooking.txt"


INT hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_address);
VOID ShowMsg();
DWORD saved_hooked_func_addr;


INT main()
{
    PCSTR func_to_hook = "CreateFileA";
    PCSTR DLL_to_hook = "KERNEL32.dll";
    DWORD new_func_address = (DWORD)&ShowMsg;
    hook(func_to_hook, DLL_to_hook, new_func_address);
    HANDLE hFile;

    // Open the file for reading
    hFile = CreateFileA
    (
        FILENAME,                                       // File name
        GENERIC_READ,                                   // Open for read
        0,                                              // Do not share
        NULL,                                           // Default security
        OPEN_EXISTING,                                  // Open only if exists
        FILE_ATTRIBUTE_NORMAL,                          // Normal file
        NULL                                            // No attr. template
    );


    // If file was not opened, print error code and return
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        printf("Error code: %d\n", error);
        return 0;
    }

    // Read some bytes and print them
    CHAR buffer[MAX];
    DWORD num;
    LPDWORD numread = &num;
    BOOL result;
    result = ReadFile
    (
        hFile,                                      // Handle to open file
        buffer,                                     // Pointer to buffer to store data
        MAX - 1,                                    // Bytes to read
        numread,                                    // Return value - bytes actually read
        NULL                                        // Overlapped
    );

    if (result == FALSE)
    {
        printf_s("There is a problem with ReadFile function: %d", GetLastError());
    }

    buffer[*numread] = 0;
    printf("%s\n", buffer);

    // Close file
    CloseHandle(hFile);

    return 0;
};


INT hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_address)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS NTHeader;
    PIMAGE_OPTIONAL_HEADER32 optionalHeader;
    IMAGE_DATA_DIRECTORY importDirectory;
    DWORD descriptorStartRVA;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
    INT index;

    // Get base address of currently running .exe
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    // Get the import directory address
    dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);

    if (((*dosHeader).e_magic) != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    // Locate NT header
    NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + (*dosHeader).e_lfanew);
    if (((*NTHeader).Signature) != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }

    // Locate optional header
    optionalHeader = &(*NTHeader).OptionalHeader;
    if (((*optionalHeader).Magic) != 0x10B)
    {
        return 0;
    }

    importDirectory = (*optionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    descriptorStartRVA = importDirectory.VirtualAddress;
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + descriptorStartRVA);

    index = 0;
    PCHAR DLL_name;

    // Look for the DLL which includes the function for hooking
    while (importDescriptor[index].Characteristics != 0)
    {
        DLL_name = (PCHAR)(baseAddress + importDescriptor[index].Name);
        printf("DLL name: %s\n", DLL_name);

        if (!strcmp(DLL_to_hook, DLL_name))
        {
            break;
        }

        index++;
    }

    // Exit if the DLL is not found in import directory
    if (importDescriptor[index].Name == 0)
    {
        printf("DLL was not found");
        return 0;
    }

    // Search for requested function in the DLL
    PIMAGE_THUNK_DATA thunkILT; // Import Lookup Table - names
    PIMAGE_THUNK_DATA thunkIAT; // Import Address Table - addresses
    PIMAGE_IMPORT_BY_NAME nameData;

    thunkILT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].OriginalFirstThunk);
    thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].FirstThunk);
    if ((thunkIAT == NULL) or (thunkILT == NULL))
    {
        return 0;
    }

    while (((*thunkILT).u1.AddressOfData != 0) && (!((*thunkILT).u1.Ordinal & IMAGE_ORDINAL_FLAG)))
    {
        nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + (*thunkILT).u1.AddressOfData);
        if (!strcmp(func_to_hook, (PCHAR)(*nameData).Name))
            break;
        thunkIAT++;
        thunkILT++;
    }

    // Hook IAT: Write over function pointer
    DWORD dwOld = NULL;
    saved_hooked_func_addr = (*thunkIAT).u1.Function;
    VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
    (*thunkIAT).u1.Function = new_func_address;
    VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), dwOld, NULL);

    return 1;
};


void ShowMsg()
{
    MessageBoxA(0, "Hooked!", "by Noam Cohen", 0);
}