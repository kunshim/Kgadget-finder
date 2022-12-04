#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

char *original_bootscript;
char *command_result;
void run_command_qemu(char *cmd, int wait);

int main(int argc, char **args)
{
	command_result = (char*)malloc(0x1000);
	char tmp_buf[1024], tmp_cmd[2048];
	int gadget_count = 0;
	memset(tmp_buf, 0, sizeof(tmp_buf));
	memset(tmp_cmd, 0, sizeof(tmp_cmd));

	if (argc != 4)
	{
		puts("Kgadget finder. Make easy to find executable gagdet.");
		puts("Usage : ./kgadget_finder <gadgets information file> <target kernel object file> <boot script path>");
		puts("Gadget information is output of the ROPgadget or rp++");
		return -1;
	}
	puts("[+] Check permission");
	int uid = getuid();
	if (uid != 0)
	{
		puts("[!] Please run as root. Because this program overwrite qemu's memory.");
		return -1;
	}

	puts("[+] Check gadget information");
	FILE *gadget_info = fopen(args[1], "r+");
	if (gadget_info == NULL)
	{
		puts("[!] Can't open gadget information file");
		return -1;
	}
	puts("[+] Check kernel object file");
	FILE *target_ko = fopen(args[2], "r");
	if (target_ko == NULL)
	{
		puts("[!] Can't open target kernel object file");
		return -1;
	}
	puts("[+] Check boot script");
	FILE *boot_script = fopen(args[3], "r+");
	if (boot_script == NULL)
	{
		puts("[!] Can't open boot script file");
		return -1;
	}
	snprintf(tmp_cmd, sizeof(tmp_cmd) ,"cp %s %s_origin", args[3], args[3]);
	system(tmp_cmd);
	puts("[+] Create named pipe");
	system("rm /tmp/kgadget_finder*");
	system("mkfifo /tmp/kgadget_finder.in /tmp/kgadget_finder.out");
	system("chmod 666 /tmp/kgadget*");

	puts("[+] Edit boot script");
	fread(tmp_buf, 1, sizeof(tmp_buf), boot_script);
	int tmp = strlen(tmp_buf);
	tmp_buf[tmp] = ' ';
	tmp_buf[tmp+1] = 0;
	strcat(tmp_buf, "-serial pipe:/tmp/kgadget_finder >> /dev/null");
	fseek(boot_script, 0, SEEK_SET);
	fwrite(tmp_buf, 1, strlen(tmp_buf), boot_script);
	/*while(1)
	{
		char *result = fgets(tmp_buf, sizeof(tmp_buf), gadget_info);
		if (!result)
			break;
		if (strstr(tmp_buf, ":"))
		{
			puts("[+] Find gadget sperator");
		}
	}*/
	fclose(boot_script);

	puts("[*] Waiting for qemu startup");
	sleep(7); //wait for qemu startup
	printf("[*] Check guest's root permission... ");
	run_command_qemu("id",1);
	if (strstr(command_result, "uid=0"))
	{
		printf("Pass\n");
	}
	//run_command_qemu("cat /proc/kallsyms",6);
	//puts(command_result);
	fclose(target_ko);
	fclose(gadget_info);
	puts("[+] Restore boot script");
	snprintf(tmp_cmd, sizeof(tmp_cmd) ,"mv %s_origin %s; chmod 777 %s", args[3], args[3], args[3]);
	system(tmp_cmd);
	system("ps -ef | grep qemu | awk '{print $2}' | xargs kill -9");
}



void run_command_qemu(char *cmd, int wait)
{
	char tmp_buf[1024];
	int out = open("/tmp/kgadget_finder.out", O_RDONLY);
	if (out < 0)
	{
		puts("[!] Error :(");
		exit(-1);
	}
	while(1)
	{
		size_t result= read(out,tmp_buf, 1024);
		if (result != 1024)
			break;
	}
	snprintf(tmp_buf, sizeof(tmp_buf), "echo %s >> /tmp/kgadget_finder.in", cmd);
	system(tmp_buf);
    sleep(wait);
    read(out, command_result, 0x1000);
    close(out);
}