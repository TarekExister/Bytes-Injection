#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <stdbool.h>

typedef long long int qword;

//function declaration
void InjectBytes(int pid, qword _ad, unsigned char* bts, size_t _amount, int hooked_bts_size);

int main(int argc, char** argv)
{
	int pid = 0x3FCC;
	qword target_address = 0x7FF66A5ABA91;
	unsigned char bytes_to_inject[14] = { 0xF3 ,0x0F ,0x58 ,0x46 ,0x20 ,0xF3 ,0x0F ,0x11 ,0x46 ,0x20 ,0x48 ,0x39 ,0x5E ,0x68 }; //hooked bytes
	InjectBytes(pid, target_address, bytes_to_inject, 14, 14);

}
//function difinition
void InjectBytes(int pid, qword _ad, unsigned char* bts, size_t _amount, int hooked_bts_size)
{
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	qword allocated_mem = VirtualAllocEx(handle, NULL, _amount+12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	qword target_address = _ad;
	qword _jmp_back_address = _ad + hooked_bts_size;

	//set jmp back
	typedef union _get_bts { qword address; unsigned char bytes[8]; }get_bts;
	unsigned char movabs_rax[2] = { 0x48,0xB8 };
	unsigned char jmp_rax[2] = { 0xFF,0xE0 };
	unsigned char jmp_back_buffer[12];
	jmp_back_buffer[0] = movabs_rax[0];
	jmp_back_buffer[1] = movabs_rax[1];
	jmp_back_buffer[10] = jmp_rax[0];
	jmp_back_buffer[11] = jmp_rax[1];
	get_bts gb;
	gb.address = _jmp_back_address;
	for (int x = 2; x < 10; x++) jmp_back_buffer[x] = gb.bytes[x - 2];
	unsigned char* bytes_to_inject = calloc(_amount + 12, sizeof(unsigned char));
	memcpy(bytes_to_inject,bts,_amount);
	for (int x = _amount; x < _amount + 12; x++) bytes_to_inject[x] = jmp_back_buffer[x - _amount];
	//write the buffer to the location of allocated mem
	WriteProcessMemory(handle, (LPVOID)allocated_mem, bytes_to_inject, _amount+12, 0);
	printf("%p\n", allocated_mem);
	//hook target address .....
	unsigned char jmpto_buffer[12];
	jmpto_buffer[0] = movabs_rax[0];
	jmpto_buffer[1] = movabs_rax[1];
	jmpto_buffer[10] = jmp_rax[0];
	jmpto_buffer[11] = jmp_rax[1];
	unsigned char *jmpto = calloc(hooked_bts_size + 12, sizeof(unsigned char));
	gb.address = allocated_mem;
	for (int x = 2; x < 10; x++) jmpto_buffer[x] = gb.bytes[x - 2];
	for (int x = 0; x < hooked_bts_size; x++) 
	{
		if (x < 12)
			jmpto[x] = jmpto_buffer[x];
		else jmpto[x] = 0x90;
	}
	WriteProcessMemory(handle, target_address,jmpto, hooked_bts_size, 0);

	free(bytes_to_inject);
	free(jmpto);
}