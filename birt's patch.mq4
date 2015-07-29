//+------------------------------------------------------------------+
//|                                                 birt's patch.mq4 |
//|                                                             birt |
//|                                              http://eareview.net |
//+------------------------------------------------------------------+
/*
    Copyright (C) 2009-2011 Cristi Dumitrescu <birt@eareview.net>
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#property copyright "birt"
#property link      "http://eareview.net"
#property show_inputs

extern string Version_0.21 = "Works only up to MT4 build 409";
extern bool NoFXTOverwrite = true;
extern bool Remove2GBLimit = true;
extern string WARNING2 = "Using variable spread with a non-variable spread FXT does NOT work.";
extern bool RealSpread = false;

#define MEM_COMMIT 0x1000
#define PAGE_EXECUTE_READWRITE 0x40
#define MAX_PATH 260

#define LAST_BUILD_KNOWN 409

#import "kernel32.dll"
   int  GetCurrentProcess();
   int  WriteProcessMemory(int handle, int address, int& buffer[], int size, int& written);
   int  ReadProcessMemory(int handle, int address, int& buffer[], int size, int& read);
   int  LoadLibraryA(string file);
   int  GetProcAddress(int hmodule, string procname);
   int  VirtualAlloc(int addr, int size, int type, int protect);
   int  GetModuleHandleA(int modName);
   int  GetModuleFileNameA(int hmod, int &buffer[], int len);
#import "Version.dll"
   int  GetFileVersionInfoSizeA(int &filename[], int h);
   bool GetFileVersionInfoA(int &filename[], int h, int len, int& lpData[]);
#import

int mt4build = 0;

//+------------------------------------------------------------------+
//| script program start function                                    |
//+------------------------------------------------------------------+
int start()
  {
//----
   if (!IsDllsAllowed()) {
      Alert("This script requires DLL calls to be enabled. Head to Tools->Options->Expert Advisors make sure Allow DLL imports is enabled and Confirm DLL function calls is disabled.");
      return(0);
   }
   mt4build = MT4build();
   Print("MT4 build " + mt4build + " detected.");
   if (mt4build > LAST_BUILD_KNOWN) {
      Alert("This script only works up to MT4 build 409 and you are using build " + mt4build);
      Alert("Consider using the Tick Data Suite (http://eareview.net/tick-data-suite) or use a MT4 client build 409 or below");
      return(0);
   }
   if (NoFXTOverwrite) fxtpatch();
   if (Remove2GBLimit) gblimit();
   if (RealSpread) spread();
//----
   return(0);
  }
//+------------------------------------------------------------------+

void fxtpatch() {
   int search1[] = { 0x83, 0xc4, 0x1c, 0x85, 0xc0, 0x0f, 0x85 };
   int search2[] = { 0x1b, 0xc0, 0x83, 0xd8, 0xff, 0x85, 0xc0, 0x0f, 0x85, 0x9d, 0x01, 0x00, 0x00 };
   // builds 405+
   int search2a[] = { 0x1b, 0xc0, 0x83, 0xd8, 0xff, 0x85, 0xc0, 0x0f, 0x85, 0x9b, 0x01, 0x00, 0x00 };
   int search3[] = { 0x8b, 0x42, 0x18, 0x85, 0xc0, 0x0f, 0x85 };
   int patchaddr1 = FindMemory(0x510000, 0x570000, search1);
   if (patchaddr1 != 0) {
      int patchaddr2 = FindMemory(patchaddr1, patchaddr1 + 32768, search2);
      if (patchaddr2 == 0) {
         patchaddr2 = FindMemory(patchaddr1, patchaddr1 + 32768, search2a);
      }
      int patchaddr3 = FindMemory(patchaddr1, patchaddr1 + 32768, search3);
   }
   if (patchaddr1 != 0 && patchaddr2 != 0 && patchaddr3 != 0) {
      int patch[] = { 0x00, 0x00 };
      PatchZone(patchaddr1 + 7, patch);
      PatchZone(patchaddr2 + 9, patch);
      PatchZone(patchaddr3 + 7, patch);
      Print("FXT overwriting disabled. Addresses patched: 0x" + Dec2Hex(patchaddr1) + ", 0x" + Dec2Hex(patchaddr2) + ", 0x" + Dec2Hex(patchaddr3) + ".");
   }
   else {
      Print("FXT overwriting already disabled or unable to find the location to patch.");
   }
}

int ProcessPatch(int address, int byte)
{
   int mem[1];
   int out;
   mem[0] = byte;
   int hproc = GetCurrentProcess();
   int result = WriteProcessMemory(hproc, address, mem, 1, out);
   return (result);
}

void PatchZone(int address, int patch[]) {
   int mem[1];
   int out;
   int hproc = GetCurrentProcess();
   for (int i = 0; i < ArraySize(patch); i++) {
      mem[0] = patch[i];
      WriteProcessMemory(hproc, address + i, mem, 1, out);
   }
   return(0);
}

int FindMemory(int start, int end, int cmp[]) {
   int mem[1];
   int out;
   int hproc = GetCurrentProcess();
   for (int i = start; i <= end; i++) {
      mem[0] = 0;
      ReadProcessMemory(hproc, i, mem, 1, out);
      if (mem[0] == cmp[0]) {
         bool found = true;
         for (int j = 1; j < ArraySize(cmp); j++) {
            mem[0] = 0;
            ReadProcessMemory(hproc, i + j, mem, 1, out);
            if (mem[0] != cmp[j]) {
               found = false;
               break;
            }
         }
         if (found) return (i);
      }
   }
   return(0);
}

void ReadDword(int addr, int& arr[]) {
   int mem[1];
   int out;
   int hproc = GetCurrentProcess();
   ReadProcessMemory(hproc, addr, mem, 1, out);
   arr[0] = mem[0];
   ReadProcessMemory(hproc, addr + 1, mem, 1, out);
   arr[1] = mem[0];
   ReadProcessMemory(hproc, addr + 2, mem, 1, out);
   arr[2] = mem[0];
   ReadProcessMemory(hproc, addr + 3, mem, 1, out);
   arr[3] = mem[0];
}

void StoreDword(int addr, int& arr[]) {
   arr[0] = addr & 0xFF;
   arr[1] = (addr & 0xFF00) >> 8;
   arr[2] = (addr & 0xFF0000) >> 16;
   arr[3] = (addr & 0xFF000000) >> 24;
}

void gblimit() {
   int h;
   int addr1 = 0;
   int addr2 = 0;
   h = LoadLibraryA("ntdll.dll");
   if (h != 0) addr2 = GetProcAddress(h, "_allmul");
   if (addr2 == 0) {
      Alert("2GB limit removal not activated.");
      Alert("Could not find the _allmul function in ntdll.dll.");
      return(0);
   }
   if (mt4build < 399) {
      string lib = "msvcrt.dll";
      h = LoadLibraryA(lib);
      if (h != 0) addr1 = GetProcAddress(h, "_fseeki64");
      if (addr1 == 0) {
         Alert("The 2GB limit removal for this build only works in Windows 7, Vista and Server 2008.");
         Alert("2GB limit removal not activated.");
         Alert("Could not find the _fseeki64() function in your msvcrt.dll!");
         return(0);
      }
      int search[] = { 0x8d, 0x14, 0x40, 0x8d, 0x04, 0x90, 0xc1, 0xe0, 0x02, 0x50, 0x51 };
      int patcharea = FindMemory(0x510000, 0x570000, search);
      if (patcharea == 0) {
         Print("Process already patched for the 2gb limit removal or we just can't find the area to patch.");
         return;
      }
      int patchaddr = patcharea;
      int calcbase = patchaddr + 5;
      int search2[] = { 0x74, 0x0A };
      int returnaddr = FindMemory(patcharea, patchaddr + 1024, search2);
   
      if (returnaddr == 0) {
         Print("Can't locate return address for 2gb patch limit removal, skipping patch.");
         return;
      }
   
      ProcessPatch(patchaddr, 0xe9);
      int new = VirtualAlloc(0, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      Print("Patch address found: 0x" + Dec2Hex(patcharea) + ". 2gb limit removal patch is being installed at 0x" + Dec2Hex(new) + ".");
      int offset = new - calcbase;
      int b[4];
      StoreDword(offset, b);
      PatchZone(patchaddr + 1, b);

      int patch[] = {0x51, 0x6a, 0x00, 0x50, 0x6a, 0x00, 0x6a, 0x34,
                      0xff, 0x15, 0xa0, 0x11, 0x54, 0x00,
                      0x59, 0x52, 0x50, 0x51,
                      0xff, 0x15, 0xa4, 0x11, 0x54, 0x00,
                      0x83, 0xc4, 0x0C,
                      0x85, 0xc0,
                      0xe9};
      PatchZone(new, patch);
      StoreDword(addr1, b);
      PatchZone(new + 128, b); // _fseeki64 goes at the alloced memory area + 128
      StoreDword(addr2, b);
      PatchZone(new + 132, b); // _allmul goes at the alloced memory area + 132
      StoreDword(new + 132, b);
      PatchZone(new + 10, b); // fix the _allmul call
      StoreDword(new + 128, b);
      PatchZone(new + 20, b); // fix the _fseeki64 call
      offset = returnaddr - (new + 30 + 4);
      StoreDword(offset, b);
      PatchZone(new + 30, b); // fix the returning jump
   }
   else if (mt4build <= 402) {
      lib = "msvcrt.dll";
      h = LoadLibraryA(lib);
      if (h != 0) addr1 = GetProcAddress(h, "_fseeki64");
      if (addr1 == 0) {
         Alert("The 2GB limit removal for this build only works in Windows 7, Vista and Server 2008.");
         Alert("2GB limit removal not activated.");
         Alert("Could not find the _fseeki64() function in your msvcrt.dll!");
         return(0);
      }

      int search3[] = { 0x8d, 0x0c, 0x40, 0x8d, 0x14, 0x88, 0x8b, 0x86, 0xd8, 0x02, 0x00 };
      patcharea = FindMemory(0x510000, 0x570000, search3);
      if (patcharea == 0) {
         Print("Process already patched for the 2gb limit removal or we just can't find the area to patch.");
         return;
      }
      patchaddr = patcharea;
      calcbase = patchaddr + 5;
      int search4[] = { 0x74, 0x0A };
      returnaddr = FindMemory(patcharea, patchaddr + 1024, search4);
      if (returnaddr == 0) {
         Print("Can't locate return address for 2gb patch limit removal, skipping patch.");
         return;
      }
   
      ProcessPatch(patchaddr, 0xe9);
      new = VirtualAlloc(0, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      Print("Patch address found: 0x" + Dec2Hex(patcharea) + ". 2gb limit removal patch is being installed at 0x" + Dec2Hex(new) + ".");
      offset = new - calcbase;
      StoreDword(offset, b);
      PatchZone(patchaddr + 1, b); // fix jump
      
      int patch1[] = {  0x6a, 0x00, 0x50, 0x6a, 0x00, 0x6a, 0x34,
                        0xff, 0x15, 0x00, 0x00, 0x00, 0x00,
                        0x52, 0x50,
                        0x8b, 0x86, 0xd8, 0x02, 0x00, 0x00,
                        0x50,
                        0xff, 0x15, 0x00, 0x00, 0x00, 0x00,
                        0x83, 0xc4, 0x10,
                        0x85, 0xc0,
                        0xe9, 0x00, 0x00, 0x00, 0x00 };
      PatchZone(new, patch1);
      StoreDword(addr1, b);
      PatchZone(new + 128, b); // _fseeki64 goes at the alloced memory area + 128
      StoreDword(addr2, b);
      PatchZone(new + 132, b); // _allmul goes at the alloced memory area + 132
      StoreDword(new + 132, b);
      PatchZone(new + 9, b); // fix the _allmul call
      StoreDword(new + 128, b);
      PatchZone(new + 24, b); // fix the _fseeki64 call
      offset = returnaddr - (new + ArraySize(patch1));
      StoreDword(offset, b);
      PatchZone(new + ArraySize(patch1) - 4, b); // fix the returning jump
   }
   else { // 405+
      lib = "msvcrt.dll";
      h = LoadLibraryA(lib);
      if (h != 0) int fseeki64 = GetProcAddress(h, "_fseeki64");
      if (fseeki64 == 0) {
         lib = "msvcr80.dll";
         h = LoadLibraryA(lib);
         if (h != 0) fseeki64 = GetProcAddress(h, "_fseeki64");
      }
      if (fseeki64 == 0) {
         lib = "msvcr90.dll";
         h = LoadLibraryA(lib);
         if (h != 0) fseeki64 = GetProcAddress(h, "_fseeki64");
      }
      if (fseeki64 == 0) {
         lib = "msvcr100.dll";
         h = LoadLibraryA(lib);
         if (h != 0) fseeki64 = GetProcAddress(h, "_fseeki64");
      }
      if (fseeki64 == 0) {
         Alert("Could not find the _fseeki64() function in your msvcrt.dll or msvcr100.dll!");
         Alert("If you're using Windows XP, consider getting a copy of the Visual C 2010 runtime, available at http://www.microsoft.com/download/en/details.aspx?id=5555 (x86) and http://www.microsoft.com/download/en/details.aspx?id=14632 (x64).");
         Alert("2GB limit removal not activated.");
         return(0);
      }
      int filelength = GetProcAddress(h, "_filelength");
      int fopen = GetProcAddress(h, "fopen");
      int fclose = GetProcAddress(h, "fclose");
      int fread = GetProcAddress(h, "fread");

      int search5[] = { 0x8d, 0x14, 0x40, 0x8d, 0x04, 0x90, 0x53, 0xc1, 0xe0, 0x02, 0x50, 0x51 };
      patcharea = FindMemory(0x510000, 0x570000, search5);
      if (patcharea == 0) {
         Print("Process already patched for the 2gb limit removal or we just can't find the area to patch.");
         return;
      }

      patchaddr = patcharea;
      calcbase = patchaddr + 6;

      int search6[] = { 0x74, 0x0A };
      returnaddr = FindMemory(patcharea, patchaddr + 1024, search6);
   
      if (returnaddr == 0) {
         Print("Can't locate return address for 2gb patch limit removal, skipping patch.");
         return;
      }

      ProcessPatch(patchaddr, 0x53);   
      ProcessPatch(patchaddr + 1, 0xe9);
      new = VirtualAlloc(0, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      int patchaddr1 = patchaddr;
      offset = new - calcbase;
      StoreDword(offset, b);
      PatchZone(patchaddr + 2, b);

      int patch3[] = {0x51, 0x6a, 0x00, 0x50, 0x6a, 0x00, 0x6a, 0x34,
                      0xff, 0x15, 0xa0, 0x11, 0x54, 0x00,
                      0x59, 0x52, 0x50, 0x51,
                      0xff, 0x15, 0xa4, 0x11, 0x54, 0x00,
                      0x83, 0xc4, 0x10,
                      0x85, 0xc0,
                      0xe9};
      PatchZone(new, patch3);
      StoreDword(fseeki64, b);
      PatchZone(new + 128, b); // _fseeki64 goes at the alloced memory area + 128
      StoreDword(addr2, b);
      PatchZone(new + 132, b); // _allmul goes at the alloced memory area + 132
      StoreDword(new + 132, b);
      PatchZone(new + 10, b); // fix the _allmul call
      StoreDword(new + 128, b);
      PatchZone(new + 20, b); // fix the _fseeki64 call
      offset = returnaddr - (new + 30 + 4);
      StoreDword(offset, b);
      PatchZone(new + 30, b); // fix the returning jump

      int search7[] = { 0x83, 0xc4, 0x24, 0x3b, 0xc3, 0x89, 0x86, 0xd8, 0x02, 0x00, 0x00 };
      patcharea = FindMemory(0x510000, 0x570000, search7);
      if (patcharea == 0) {
         Alert("Failed to fully patch the 2GB limit!");
         Alert("Backtesting will probably result in a crash!");
         return;
      }
      offset = fopen - patcharea;
      patcharea -= 4;
      int patchaddr2 = patcharea - 1;
      StoreDword(offset, b);
      PatchZone(patcharea, b);

      int search8[] = { 0x83, 0xc4, 0x04, 0x89, 0x9e, 0xd8, 0x02, 0x00, 0x00, 0x8b, 0x86, 0x04, 0x03, 0x00, 0x00 };
      patcharea = FindMemory(0x510000, 0x570000, search8);
      if (patcharea == 0) {
         Alert("Failed to fully patch the 2GB limit!");
         Alert("Backtesting will probably result in a crash!");
         return;
      }
      offset = fclose - patcharea;
      patcharea -= 4;
      int patchaddr3 = patcharea - 1;
      StoreDword(offset, b);
      PatchZone(patcharea, b);
      
      int search8a[] = { 0x83, 0xc4, 0x04, 0x89, 0x9e, 0xd8, 0x02, 0x00, 0x00, 0x8d, 0x84, 0x24, 0x1c, 0x08, 0x00, 0x00 };
      patcharea = FindMemory(0x510000, 0x570000, search8a);
      if (patcharea == 0) {
         Alert("Failed to fully patch the 2GB limit!");
         Alert("Backtesting will probably result in a crash!");
         return;
      }
      offset = fclose - patcharea;
      patcharea -= 4;
      int patchaddr3a = patcharea - 1;
      StoreDword(offset, b);
      PatchZone(patcharea, b);
      
      int search8b[] = { 0x83, 0xc4, 0x04, 0xc7, 0x85, 0xd8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b };
      patcharea = FindMemory(0x510000, 0x570000, search8b);
      if (patcharea == 0) {
         Alert("Failed to fully patch the 2GB limit!");
         Alert("Backtesting will probably result in a crash!");
         return;
      }
      offset = fclose - patcharea;
      patcharea -= 4;
      int patchaddr3b = patcharea - 1;
      StoreDword(offset, b);
      PatchZone(patcharea, b);

      int search9[] = { 0x8d, 0x04, 0x7f, 0x8d, 0x0c, 0x87, 0x6a, 0x01, 0xc1, 0xe1, 0x02, 0x51, 0x52, 0xe8 };
      patcharea = FindMemory(0x510000, 0x570000, search9);
      if (patcharea == 0) {
         Alert("Failed to fully patch the 2GB limit!");
         Alert("Backtesting will probably result in a crash!");
         return;
      }
      patcharea += 18;
      offset = fread - patcharea;
      patcharea -= 4;
      int patchaddr4 = patcharea - 1;
      StoreDword(offset, b);
      PatchZone(patcharea, b);

      int search10[] = { 0x8b, 0xc8, 0x81, 0xe9, 0xd8, 0x02, 0x00, 0x00, 0xb8, 0x4f, 0xec, 0xc4, 0x4e, 0xf7, 0xe1, 0x83, 0xc4, 0x04 };
      patcharea = FindMemory(0x510000, 0x570000, search10);
      if (patcharea == 0) {
         Alert("Failed to fully patch the 2GB limit!");
         Alert("Backtesting will probably result in a crash!");
         return;
      }
      offset = filelength - patcharea;
      patcharea -= 4;
      int patchaddr5 = patcharea - 1;
      StoreDword(offset, b);
      PatchZone(patcharea, b);
      Print("Patched: fseek 0x" + Dec2Hex(patchaddr1) + ", fopen 0x" + Dec2Hex(patchaddr2) +  ", fclose 0x" + Dec2Hex(patchaddr3) + ", fclose 0x" + Dec2Hex(patchaddr3a) + ", fclose 0x" + Dec2Hex(patchaddr3b) + ", fread 0x" + Dec2Hex(patchaddr4) +  ", filelength 0x" + Dec2Hex(patchaddr5) + ". 2gb limit removal patch was installed at 0x" + Dec2Hex(new) + ".");
   }
}

void spread() {

   int search[] = { 0x02, 0x00, 0x00,
                    0xdd, 0x42, 0x1c,
                    0xdc, 0x83, 0x20, 0x03, 0x00, 0x00 };
   int patcharea = FindMemory(0x510000, 0x570000, search);
   if (patcharea != 0) {
      int patchaddr = patcharea + 6;

      int patch[] = { 0xdc, 0x42, 0x24, 0x90, 0x90, 0x90 };
      PatchZone(patchaddr, patch);
   }
   else {
      int search1a[] = { 0x02, 0x00, 0x00,
                        0xdd, 0x42, 0x1c,
                        0x8b, 0x54, 0x24, 0x20,
                        0xdc, 0x83, 0x20, 0x03, 0x00, 0x00 };
      patcharea = FindMemory(0x510000, 0x570000, search1a);
      if (patcharea != 0) {
         patchaddr = patcharea + 6;
      }
      int patch1[] = { 0xdc, 0x42, 0x24, 0x8b, 0x54, 0x24, 0x20, 0x90, 0x90, 0x90 };
      PatchZone(patchaddr, patch1);
   }
   if (patcharea == 0) {
      Print("Process already patched for variable spread or we just can't find the area to patch.");
      return;
   }

   int search2[] = { 0xdf, 0xe0, 0xf6, 0xc4, 0x41, 0x75, 0x40, 0x4f, 0x83, 0xc1, 0x34, 0x3b, 0xfb };
   int patcharea2 = FindMemory(0x510000, 0x570000, search2);
   string volstr;
   if (patcharea2 != 0) {
      ProcessPatch(patcharea2 + 6, 0); // remove the volume check
      volstr = " Volume check removed at 0x" + Dec2Hex(patcharea2 + 6) + ".";
   }
   else {
      Print("Volume check NOT removed. You may encounter problems when spread is 0.");
   }
   Print("Process patched for variable spread at 0x" + Dec2Hex(patchaddr) + "." + volstr);
}

string Dec2Hex(int n) {
   string result = "";
   while(n > 0) {
      int d = n % 16;
      string c;
      if (d == 10) {
         c = "A";
      }
      else if (d == 11) {
         c = "B";
      }
      else if (d == 12) {
         c = "C";
      }
      else if (d == 13) {
         c = "D";
      }
      else if (d == 14) {
         c = "E";
      }
      else if (d == 15) {
         c = "F";
      }
      else {
         c = d;
      }
      result = c + result;
      n = n / 16;
   }
   return (result);
}

int MT4build() {
   int vSize, vInfo[];
   int hMod = GetModuleHandleA(0);
   int exePath[];
   ArrayResize(exePath, MAX_PATH/4);
   GetModuleFileNameA(hMod, exePath, MAX_PATH);
   string vChar[4];
   vSize = GetFileVersionInfoSizeA(exePath, 0);
   ArrayResize(vInfo, vSize / 4);
   GetFileVersionInfoA(exePath, 0, vSize, vInfo);
   string vString = "";
   for(int i = 0; i < vSize / 4; i++){
      vChar[0] = CharToStr(vInfo[i] & 0x000000FF);
      vChar[1] = CharToStr(vInfo[i] >>  8 & 0x000000FF);
      vChar[2] = CharToStr(vInfo[i] >> 16 & 0x000000FF);
      if(vChar[0] == "" && vChar[3] == "") vString = vString + " ";
      else vString = vString + vChar[0];
      vChar[3] = CharToStr(vInfo[i] >> 24 & 0x000000FF);
      if(vChar[1] == "" && vChar[0] == "") vString = vString + " ";
      else vString = vString + vChar[1];
      if(vChar[2] == "" && vChar[1] == "") vString = vString + " ";
      else vString = vString + vChar[2];
      if(vChar[3] == "" && vChar[2] == "") vString = vString + " ";
      else vString = vString + vChar[3];
   }
   vString = StringTrimRight(StringTrimLeft(StringSubstr(vString, StringFind(vString, "FileVersion") + 11, 15)));
   for (i = 0; i < 3; i++) {
      vString = StringSubstr(vString, StringFind(vString, ".") + 1);
   }
   int build = StrToInteger(vString);
   return (build);
}