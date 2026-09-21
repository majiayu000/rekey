#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/io_uring.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
static void result(const char *name,long value) {int error=errno;printf("%s=%ld errno=%d\n",name,value,error);}
static void *thread(void *arg){return arg;}
int main(int argc,char **argv) {
 setbuf(stdout,NULL);
 char input[4096]={0};
 if(argc>1)snprintf(input,sizeof(input),"%s",argv[1]);
 else if(fread(input,1,sizeof(input)-1,stdin)==0){
  /* Empty stdin is the before-READY fixture: stay alive after parent death
     unless the sandbox first hop or namespace reaps this process. */
  signal(SIGTERM,SIG_IGN);signal(SIGHUP,SIG_IGN);
  struct timespec delay={.tv_sec=1};for(;;)nanosleep(&delay,NULL);
 }
 if(!strcmp(input,"ok")) {puts("OK");return 0;}
 if(!strcmp(input,"env")) {extern char **environ;for(char **entry=environ;*entry;entry++)puts(*entry);return 0;}
 if(!strncmp(input,"fd ",3)) {int fd=atoi(input+3);printf("fd=%d open=%d\n",fd,fcntl(fd,F_GETFD)>=0);return 0;}
 if(!strcmp(input,"fds")) {int count=0;for(int fd=3;fd<1024;fd++)if(fcntl(fd,F_GETFD)>=0)count++;printf("fds=%d\n",count);return 0;}
 if(!strncmp(input,"read ",5)) {errno=0;int fd=open(input+5,O_RDONLY);result("read",fd<0?-1:0);if(fd>=0)close(fd);return 0;}
 if(!strncmp(input,"write ",6)) {errno=0;int fd=open(input+6,O_WRONLY|O_CREAT,0600);result("write",fd<0?-1:0);if(fd>=0)close(fd);return 0;}
 if(!strncmp(input,"tcp ",4)) {errno=0;int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0){result("socket",-1);return 0;}struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(input+4)),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};result("connect",connect(fd,(void*)&a,sizeof(a)));close(fd);return 0;}
 if(!strncmp(input,"unix ",5)) {errno=0;int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0){result("socket",-1);return 0;}struct sockaddr_un a={.sun_family=AF_UNIX};snprintf(a.sun_path,sizeof(a.sun_path),"%s",input+5);result("connect",connect(fd,(void*)&a,sizeof(a)));close(fd);return 0;}
 if(!strcmp(input,"syscalls")) {
  errno=0;pid_t p=fork();if(!p)_exit(0);result("fork",p<0?-1:0);if(p>0)waitpid(p,NULL,0);
  struct clone_args a={.exit_signal=SIGCHLD};errno=0;long c=syscall(SYS_clone3,&a,sizeof(a));if(c==0)_exit(0);result("clone3",c<0?-1:0);if(c>0)waitpid((pid_t)c,NULL,0);
  errno=0;result("unshare",syscall(SYS_unshare,0));
  errno=0;int fd=syscall(SYS_memfd_create,"test",0);result("memfd",fd<0?-1:0);if(fd>=0)close(fd);
  return 0;
 }
 if(!strcmp(input,"restricted")) {
  pthread_t t;int error=pthread_create(&t,NULL,thread,NULL);printf("thread=%d\n",error);if(!error)pthread_join(t,NULL);
  errno=0;int fd=syscall(SYS_pidfd_open,getpid(),0);result("pidfd",fd<0?-1:0);if(fd>=0)close(fd);
  char value='x',copy=0;struct iovec local={&copy,1},remote={&value,1};errno=0;result("process_vm",process_vm_readv(getpid(),&local,1,&remote,1,0));
  struct io_uring_params params={0};errno=0;fd=syscall(SYS_io_uring_setup,1,&params);result("io_uring",fd<0?-1:0);if(fd>=0)close(fd);
  errno=0;result("ptrace",ptrace(PTRACE_TRACEME,0,NULL,NULL));return 0;
 }
 if(!strcmp(input,"execveat")) {char *args[]={argv[0],"ok",NULL};char *env[]={NULL};errno=0;syscall(SYS_execveat,AT_FDCWD,argv[0],args,env,0);result("execveat",-1);return 0;}
 if(!strcmp(input,"limits")||!strcmp(input,"selfexec")||!strcmp(input,"afterexec")) {
  struct rlimit r;if(getrlimit(RLIMIT_AS,&r))return 91;printf("as=%llu/%llu\n",(unsigned long long)r.rlim_cur,(unsigned long long)r.rlim_max);
  if(!strcmp(input,"selfexec")){char *args[]={argv[0],"afterexec",NULL};char *env[]={NULL};execve(argv[0],args,env);return 92;}
  if(r.rlim_max!=RLIM_INFINITY){struct rlimit raised={96UL*1024*1024,96UL*1024*1024};errno=0;result("raise",setrlimit(RLIMIT_AS,&raised));}
  errno=0;void *p=mmap(NULL,96UL*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);result("mmap96",p==MAP_FAILED?-1:0);
  if(p!=MAP_FAILED){for(size_t i=0;i<96UL*1024*1024;i+=4096)((volatile char*)p)[i]=1;munmap(p,96UL*1024*1024);}
  errno=0;int fd=socket(AF_INET,SOCK_STREAM,0);result("socket",fd<0?-1:0);if(fd>=0)close(fd);return 0;
 }
 if(!strcmp(input,"cpu")){signal(SIGXCPU,SIG_IGN);puts("READY");for(;;){}}
 if(!strcmp(input,"orphan")) {
  errno=0;result("clear_pdeathsig",prctl(PR_SET_PDEATHSIG,0));
  errno=0;result("setsid",setsid()<0?-1:0);
  signal(SIGTERM,SIG_IGN);signal(SIGHUP,SIG_IGN);puts("READY");
  struct timespec delay={.tv_sec=1};for(;;)nanosleep(&delay,NULL);
 }
 if(!strcmp(input,"overflow")){for(int i=0;i<300000;i++)putchar('x');return 0;}
 if(!strcmp(input,"crash")){raise(SIGABRT);return 93;}
 if(!strcmp(input,"external_exec")){char *args[]={"/bin/true",NULL};char *env[]={NULL};errno=0;execve(args[0],args,env);result("exec",-1);return 0;}
#if defined(__x86_64__)
 if(!strcmp(input,"x32")){syscall(0x40000000|SYS_getpid);puts("ESCAPED");return 0;}
 if(!strcmp(input,"i386")){__asm__ volatile("int $0x80" : : "a"(20) : "memory");puts("ESCAPED");return 0;}
#endif
 return 94;
}
