/***
 * 
 * java_block_java_security.c
 * 
 * Author: jkolczasty@gmail.com
 * 
 * Block stat on java.security to disable java security. Written for exclusive use for connection
 * to old KVM devices with old hashes like MD5 without compromising system-wide java.security config.
 * 
 * COMPILE: gcc -fPIC -shared -o java_block_java_security.so -ldl java_block_java_security.c
 * 
 * USAGE: export LD_PRELOAD=./java_block_java_security.c;  javaws.itweb kvm.jnlp
 * 
 * LICENSE: MIT
 */


#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
// #include <sys/types.h>
#include <sys/stat.h>
// #include <unistd.h>
#include <sys/vfs.h>

int (*r___xstat)(int ver, const char *path, struct stat *buf)=NULL;
int (*r___xstat64)(int ver, const char *path, struct stat64 *buf)=NULL;

int (*r___lxstat)(int ver, const char *path, struct stat *buf)=NULL;
int (*r___lxstat64)(int ver, const char *path, struct stat64 *buf)=NULL;


__attribute__((constructor)) void init(void)
{
    puts("### Intercept java.security active");
};

int __xstat(int ver, const char *path, struct stat *buf)
{
    int l = strlen(path);
    if (l<=0)
    {
        return -1;
    };
    
    if (r___xstat==NULL)
    {
        r___xstat = dlsym(RTLD_NEXT, "__xstat");
    };
    
    if ((l>14) && (strcmp(path + l - 14, "/java.security")==0))
    {
        puts("### Intercept __xstat of java.security");
        return -1;
    };
    
    return r___xstat(ver, path, buf);
};


int __xstat64(int ver, const char *path, struct stat64 *buf)
{
    int l = strlen(path);

    if (r___xstat64==NULL)
    {
        r___xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    };
    
    if ((l>14) && (strcmp(path + l - 14, "/java.security")==0))
    {
        puts("### Intercept __xstat64 of java.security");
        return -1;
    };
    
    return r___xstat64(ver, path, buf);
};


int __lxstat(int ver, const char *path, struct stat *buf)
{
    int l = strlen(path);

    if (r___lxstat==NULL)
    {
        r___lxstat = dlsym(RTLD_NEXT, "__lxstat");
    };
    
    if ((l>14) && (strcmp(path + l - 14, "/java.security")==0))
    {
        puts("Intercept __lxstat of java.security");
        return -1;
    };
    
    return r___lxstat(ver, path, buf);
};


int __lxstat64(int ver, const char *path, struct stat64 *buf)
{
    int l = strlen(path);
    
    if (r___lxstat64==NULL)
    {
        r___lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    };
    
    if ((l>14) && (strcmp(path + l - 14, "/java.security")==0))
    {
        puts("Intercept __lxstat64 of java.security");
        return -1;
    };
    
    return r___lxstat64(ver, path, buf);
};
