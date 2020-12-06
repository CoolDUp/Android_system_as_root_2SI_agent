#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/un.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/system_properties.h>

// 凑合着用吧,没那么多讲究，magisk里抄的文件操作函数。
// 不用设置selinux file context 也没毛病
#ifdef USE_SELINX
#include <selinux/selinux.h>
#else
#define lgetfilecon(x,y) 0
#define fgetfilecon(x,y) 0
#define lsetfilecon(x,y) 0
#define fsetfilecon(x,y) 0
#define freecon(x) 0
#endif

struct file_attr {
	struct stat st;
	char con[128];
};

typedef struct file_attr file_attr;

int getattr(const char *path, file_attr *a) {
	if (lstat(path, &a->st) == -1)
		return -1;
	char *con;
	if (lgetfilecon(path, &con) == -1)
		return -1;
	strcpy(a->con, con);
	freecon(con);
	return 0;
}

int setattr(const char *path, file_attr *a) {
	if (chmod(path, a->st.st_mode & 0777) < 0)
		return -1;
	if (chown(path, a->st.st_uid, a->st.st_gid) < 0)
		return -1;
	if (a->con[0] && lsetfilecon(path, a->con) < 0)
		return -1;
	return 0;
}

void clone_attr(const char *src, const char *dest) {
	file_attr a;
	getattr(src, &a);
	setattr(dest, &a);
}

int fgetattr(int fd, file_attr *a) {
	if (fstat(fd, &a->st) < 0)
		return -1;
	char *con;
	if (fgetfilecon(fd, &con) < 0)
		return -1;
	strcpy(a->con, con);
	freecon(con);
	return 0;
}

int fsetattr(int fd, file_attr *a) {
	if (fchmod(fd, a->st.st_mode & 0777) < 0)
		return -1;
	if (fchown(fd, a->st.st_uid, a->st.st_gid) < 0)
		return -1;
	if (a->con[0] && fsetfilecon(fd, a->con) < 0)
		return -1;
	return 0;
}

void fclone_attr(int src, int dest) {
	file_attr a;
	fgetattr(src, &a);
	fsetattr(dest, &a);
}

int copyFile(const char* src, const char* des, int cp_attr)
{
	int nRet = 0;
	FILE* pSrc = NULL, *pDes = NULL;
	pSrc = fopen(src, "r");
	pDes = fopen(des, "w+");
	if (pSrc && pDes)
	{
		int nLen = 0;
		char szBuf[1024] = {0};
		while((nLen = fread(szBuf, 1, sizeof szBuf, pSrc)) > 0)
		{
			fwrite(szBuf, 1, nLen, pDes);
		}
	}
	else
		nRet = -1;
	if(!nRet && cp_attr) clone_attr(src,des);
	if (pSrc)
		fclose(pSrc), pSrc = NULL;
	if (pDes)
		fclose(pDes), pDes = NULL;
	return nRet;
}

// 谁给换个高级点的版本
int bpatch(const char* filename, const char* old, const char* new, size_t size, size_t max_count){
	FILE *p = 0;
	char* buf = 0;
	size_t fsize = 0,count = 0;

	p = fopen(filename, "rb+");
	if(!p) return -1;
	fseek(p, 0, SEEK_END);
	fsize = ftell(p);
	fseek(p, 0, SEEK_SET);
	buf = calloc(fsize,1);
	if(!buf){
		fclose(p);
		return -2;
	}
	fread(buf, 1, fsize, p);
	for(int i = 0; i < fsize; i++){
		if(!memcmp(buf + i, old, size)){
			fseek(p, i, SEEK_SET);
			fwrite(new, 1, size, p);
			// printf("replace %s at 0x%x\n", old, i);
			i += size;
			count++;
			if(count == max_count) break;
		}
	}
	free(buf);
	fclose(p);
	return 0;
}

static int __setcon(const char *ctx) {
	int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return fd;
	size_t len = strlen(ctx) + 1;
	int rc = write(fd, ctx, len);
	close(fd);
	return rc != len;
}

void force_open_adb(){
	if(fork()) return;	
	sleep(20);
	// wait selinux_setup and system_property_init  completed
  // 具体看你设备的sepolicy是怎么定的,用了magiskinit可以直接u:r:magisk:s0,或者直接给kernel打补丁,弄个permssive=1
	//__setcon("u:r:vendor_init:s0");
	__setcon("u:r:magisk:s0");
	__system_property_set("sys.usb.config", "none");
	sleep(3);
  // 设置成什么看你init.configfs.rc
	__system_property_set("sys.usb.config", "manufacture,adb");
	exit(0);
}

int main(int argc, char *argv[])
{
	#define CHECKCALL(x) \
	if (x != 0) {puts(#x " failed"); exit(1);}
	
	if(argc > 1){
		if(!strcmp(argv[1],"selinux_setup")){
				/*
				when you debug
				put agent into "/.files/magiskinit"
				can test something here
				or you just want get root
				use magiskinit/magiskinit64
				*/
				// something start
				// use adbd have patch debug build check
				if(access("/system/bin/adbd", F_OK) == 0){
					mount("/debug_ramdisk/adbd", "/system/bin/adbd", 0, MS_BIND, 0);
					force_open_adb();	
				}
        // if magiskinit exists , exec it
				if(access("/debug_ramdisk/magiskinit", X_OK) == 0)
					execv("/debug_ramdisk/magiskinit", argv);
				// something end
				execv("/init", argv);
				return 1;
		}
	}
	// patch origin init data
	// use WinHex to replace these
	// 1."/debug_ramdisk" -> "/apex"  avoid /debug_ramdisk mount again
	// 2."/system/bin/init" -> "/debug_ramdisk/I" let first_stage_init load our own init
	CHECKCALL(bpatch("init_origin","/debug_ramdisk", "/apex", 15, 1));
	CHECKCALL(bpatch("init_origin","/system/bin/init", "/debug_ramdisk/I", 17, 1));
	// mount debug_ramdisk because debug_ramdisk will mount by first_stage_init at new root
	CHECKCALL(mount("tmpfs", "/debug_ramdisk", "tmpfs", 0, "mode=755"));
	// copy need files.(clone origin file and attr to new)
	CHECKCALL(copyFile("/.files/init", "/debug_ramdisk/I", 1));
	copyFile("/.files/adbd", "/debug_ramdisk/adbd", 1);
	copyFile("/.files/magiskinit", "/debug_ramdisk/magiskinit", 1);
	// recover origin init and execute it
	CHECKCALL(rename("/init_origin", "/init"));
	execv("/init", argv);
	return 1;
}
