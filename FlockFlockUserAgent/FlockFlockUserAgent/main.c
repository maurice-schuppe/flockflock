//
//  main.c
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//


#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <errno.h>
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <libproc.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#define DEFAULT_FLOCKFLOCKRC "/Library/Application Support/FlockFlock/.flockflockrc"

io_connect_t driverConnection;
pthread_mutex_t lock, prompt_lock;

#include "../../FlockFlockKext/FlockFlock/FlockFlockClientShared.h"

enum FlockFlockPolicyClass get_class_by_name(const char *name) {

    if (!strcmp(name, "allow"))
        return kFlockFlockPolicyClassWhitelistAllMatching;
    if (!strcmp(name, "deny"))
        return kFlockFlockPolicyClassBlacklistAllMatching;
    if (!strcmp(name, "allow!"))
        return kFlockFlockPolicyClassWhitelistAllNotMatching;
    if (!strcmp(name, "deny!"))
        return kFlockFlockPolicyClassBlacklistAllNotMatching;
    return kFlockFlockPolicyClassCount;
}

enum FlockFlockPolicyType get_type_by_name(const char *name) {
    
    if (!strcmp(name, "prefix"))
        return kFlockFlockPolicyTypePathPrefix;
    if (!strcmp(name, "path"))
        return kFlockFlockPolicyTypeFilePath;
    if (!strcmp(name, "suffix"))
        return kFlockFlockPolicyTypePathSuffix;
    return kFlockFlockPolicyTypeCount;
}

int send_configuration(io_connect_t connection)
{
    char path[PATH_MAX];
    char *home;
    struct _FlockFlockClientPolicy rule;
    
    home = getenv("HOME");
    if (! home) {
        struct passwd* pwd = getpwuid(getuid());
        if (pwd)
            home = pwd->pw_dir;
    }
    if (home) {
        snprintf(path, sizeof(path), "%s/.flockflockrc", home);
    } else {
        fprintf(stderr, "unable to determine home directory\n");
        return errno;
    }
    
    FILE *file = fopen(path, "r");
    char buf[2048];
    if (!file) {
        file = fopen(DEFAULT_FLOCKFLOCKRC, "r");
        if (file) {
            FILE *out = fopen(path, "w");
            if (!out) {
                fprintf(stderr, "unable to open '%s' for writing: %s (%d)\n", path, strerror(errno), errno);
                return errno;
            }
            while((fgets(buf, sizeof(buf), file))!=NULL) {
                fprintf(out, "%s", buf);
            }
            fclose(out);
            fclose(file);
            file = fopen(path, "r");
        }
        
        if (!file) {
            fprintf(stderr, "unable to open '%s' for reading: %s (%d)\n", path, strerror(errno), errno);
            return errno;
        }
    }

    kern_return_t kr = IOConnectCallMethod(connection, kFlockFlockRequestClearConfiguration, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "unable to clear old configuration, aborting\n");
        return E_FAIL;
    }

    while((fgets(buf, sizeof(buf), file))!=NULL) {
        if (buf[0] == '#' || buf[0] == ';')
            continue;
        if (buf[0] == 0 || buf[0] == '\r' || buf[0] == '\n')
            continue;
        
        char *class = strtok(buf, "\t ");
        char *type = strtok(NULL, "\t ");
        char *path = strtok(NULL, "\"");
        char *pname = strtok(NULL, "\"");
        pname = strtok(NULL, "\"");
        char *temp = strtok(NULL, "\t\n ");
        
        printf("adding rule: class %s type %s path \"%s\" process name \"%s\" temporary %s\n", class, type, path, pname, temp);
    
        rule.ruleClass = get_class_by_name(class);
        rule.ruleType = get_type_by_name(type);
        if (!strcmp(path, "any")) {
            rule.rulePath[0] = 0;
        } else {
            strncpy(rule.rulePath, path, PATH_MAX);
        }
        
        if (!strcmp(pname, "any")) {
            rule.processName[0] = 0;
        } else {
            strncpy(rule.processName, pname, PATH_MAX);
        }
        
        if (!strncmp(temp, "no", 2) || atoi(temp)==0) {
            rule.temporaryPid = 0;
            rule.temporaryRule = 0;
        } else {
            rule.temporaryPid = atoi(temp);
            rule.temporaryRule = 1;
        }
        
        printf("class: %d\n", get_class_by_name(class));
        printf("type : %d\n", get_type_by_name(type));
        printf("path : %s\n", rule.rulePath);
        printf("proc : %s (%d)\n", rule.processName, (int)strlen(rule.processName));
        printf("temp : %d\n", rule.temporaryRule);
        
        kern_return_t kr = IOConnectCallMethod(connection, kFlockFlockRequestAddClientRule, NULL, 0, &rule, sizeof(rule), NULL, NULL, NULL, NULL);
        if (kr == KERN_SUCCESS) {
            printf("\tsuccess\n");
        } else {
            printf("\tfailed\n");
        }
    }
    fclose(file);
    return 0;
}

int start_filter(io_connect_t connection)
{
    return IOConnectCallMethod(connection, kFlockFlockRequestStartFilter, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
}

int stop_filter(io_connect_t connection)
{
    return IOConnectCallMethod(connection, kFlockFlockRequestStopFilter, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
}

void stop(void) {
    printf("stopping filter\n");
    stop_filter(driverConnection);
}

int get_ppid(int pid)
{
    struct kinfo_proc info;
    size_t length = sizeof(struct kinfo_proc);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &info, &length, NULL, 0) < 0)
        return UINT_MAX;
    if (length == 0)
        return UINT_MAX;
    return info.kp_eproc.e_ppid;
}

int write_new_rule(struct _FlockFlockClientPolicy *rule)
{
    char path[PATH_MAX];
    char rule_data[PATH_MAX * 4];
    char *home;
    FILE *file;
    
    home = getenv("HOME");
    if (! home) {
        struct passwd* pwd = getpwuid(getuid());
        if (pwd)
            home = pwd->pw_dir;
    }
    if (home) {
        snprintf(path, sizeof(path), "%s/.flockflockrc", home);
    } else {
        fprintf(stderr, "unable to determine home directory\n");
        return errno;
    }
    snprintf(rule_data, sizeof(rule_data), "%s %s \"%s\" \"%s\" no",
             (rule->ruleClass == kFlockFlockPolicyClassWhitelistAllMatching) ? "allow" : "deny",
             (rule->ruleType == kFlockFlockPolicyTypeFilePath) ? "path" :
                (rule->ruleType == kFlockFlockPolicyTypePathPrefix) ? "prefix" : "suffix",
             (rule->rulePath[0]) ? rule->rulePath : "any",
             (rule->processName[0]) ? rule->processName : "any");
    
    printf("ADD:\n%s\n", rule_data);
    file = fopen(path, "a");
    if (file) {
        fprintf(file, "%s\n", rule_data);
        fclose(file);
    }
    return 0;
}

int prompt_user_response(struct policy_query *query)
{
    char proc_path[PATH_MAX], pproc_path[PATH_MAX];
    int ppid = get_ppid(query->pid);
    struct _FlockFlockClientPolicy rule;
    char alert_message[4096];
    CFStringRef alert_str, param;
    CFUserNotificationRef notification;
    CFDictionaryRef parameters;
    CFMutableArrayRef popup_options, radio_options;
    CFOptionFlags responseFlags = 0;
    unsigned long selectedIndex;
    CFStringRef selectedElement;
    SInt32 err, response;
    char *path, *extension, *ptr, option[PATH_MAX];
    int i;
    

    strncpy(proc_path, query->process_name, PATH_MAX-1);
    proc_pidpath(ppid, pproc_path, PATH_MAX);
    
    snprintf(alert_message, sizeof(alert_message), "FlockFlock detected an access attempt to the file '%s'\n\nApplication:\n%s (%d)\n\nParent:\n%s (%d)\n",
             query->path, proc_path, query->pid, pproc_path, ppid);
    alert_str = CFStringCreateWithCStringNoCopy(NULL, alert_message, kCFStringEncodingUTF8, NULL);
    printf("%s\n", alert_message);
    
    CFStringRef base = CFSTR("file:///Library/Application%20Support/FlockFlock/lock.png");
    CFURLRef icon = CFURLCreateWithString(NULL, base, NULL);
    
    /* construct path dropdown */
    popup_options = CFArrayCreateMutable(NULL, 0, NULL);
    
    /* find extension */
    ptr = query->path + strlen(query->path)-1;
    while(ptr >= query->path && ptr[0] != '/') {
        ptr--;
    }
    extension = strchr(ptr, '.');
    if (extension) {
        snprintf(option, sizeof(option), "All %s Files", extension);
        param = CFStringCreateWithCString(NULL, option, kCFStringEncodingUTF8);
        CFArrayAppendValue(popup_options, param);
    }
    
    snprintf(option, sizeof(option), "Only %s", query->path);
    param = CFStringCreateWithCString(NULL, option, kCFStringEncodingUTF8);
    CFArrayAppendValue(popup_options, param);
    
    path = strdup(query->path);
    int dir = 0;
    for(i = (int)strlen(path)-1; i>=0; --i) {
        if (path[i] == '/') {
            path[i+1] = 0;
            if (!dir) {
                snprintf(option, sizeof(option), "Only Files in %s", path);
                param = CFStringCreateWithCString(NULL, option, kCFStringEncodingUTF8);
                CFArrayAppendValue(popup_options, param);
            }
            dir = 1;
            snprintf(option, sizeof(option), "Files Nested in %s", path);
            if (!strcmp(path, "/")) {
                strcpy(option, "Any Files");
            }
            param = CFStringCreateWithCString(NULL, option, kCFStringEncodingUTF8);
            CFArrayAppendValue(popup_options, param);
        }
    }
    free(path);
    
    /* construct the popup */
    radio_options = CFArrayCreateMutable(NULL, 0, NULL);
    CFArrayAppendValue(radio_options, CFSTR("Once"));
    CFArrayAppendValue(radio_options, CFSTR("Until Restart"));
    CFArrayAppendValue(radio_options, CFSTR("Forever"));
    
    const void* keys[] = {
        kCFUserNotificationAlertHeaderKey,
        kCFUserNotificationAlertMessageKey,
        kCFUserNotificationDefaultButtonTitleKey,
        kCFUserNotificationAlternateButtonTitleKey,
        kCFUserNotificationPopUpTitlesKey,
        kCFUserNotificationCheckBoxTitlesKey,
        kCFUserNotificationIconURLKey
    };
    
    const void* values[] = {
        CFStringCreateWithCString(NULL, proc_path, kCFStringEncodingUTF8),
        alert_str,
        CFSTR("Allow"),
        CFSTR("Deny"),
        popup_options,
        radio_options,
        icon
    };
    
    /* display the popup to the user and get a response */
    parameters = CFDictionaryCreate(0, keys, values, sizeof(keys)/sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    notification = CFUserNotificationCreate(kCFAllocatorDefault, 60, kCFUserNotificationPlainAlertLevel | CFUserNotificationPopUpSelection((extension == NULL) ? 0 : 1) | kCFUserNotificationUseRadioButtonsFlag | CFUserNotificationCheckBoxChecked(2), &err, parameters);
    response = CFUserNotificationReceiveResponse(notification, 60, &responseFlags);
    
    if (response != 0) {
        printf("query timed out. denying access.\n");
        return EACCES;
    }
    
    /* allow / deny */
    if ((responseFlags & 0x03) == kCFUserNotificationDefaultResponse) {
        rule.ruleClass = kFlockFlockPolicyClassWhitelistAllMatching;
    } else if ((responseFlags & 0x03) == kCFUserNotificationAlternateResponse) {
        rule.ruleClass = kFlockFlockPolicyClassBlacklistAllMatching;
    } else {
        printf("invalid response. denying access.\n");
        return EACCES;
    }
    
    /* path selection */
    selectedIndex = (responseFlags >> 24);
    selectedElement = CFArrayGetValueAtIndex(popup_options, selectedIndex);
    if (selectedIndex < 2 + ((extension == NULL) ? 0 : 1)) {    /* exact paths / extensions */
        const char *path = (const char *)CFStringGetCStringPtr(selectedElement, kCFStringEncodingUTF8);
        if (extension && selectedIndex == 0) {
            rule.ruleType = kFlockFlockPolicyTypePathSuffix;
            strncpy(rule.rulePath, extension, sizeof(rule.rulePath)-1);

        } else {
            path = strchr(path, '/');
            rule.ruleType = kFlockFlockPolicyTypeFilePath;
            strncpy(rule.rulePath, path, sizeof(rule.rulePath)-1);
        }
    } else {
        const char *path = (const char *)CFStringGetCStringPtr(selectedElement, kCFStringEncodingUTF8);
        path = strchr(path, '/');
        if (!path) {
            path = "/";
        }
        strncpy(rule.rulePath, path, sizeof(rule.rulePath)-1);
        rule.ruleType = kFlockFlockPolicyTypePathPrefix;
        if (!strcmp(rule.rulePath, "/"))
            rule.rulePath[0] = 0; /* any */
    }

    strncpy(rule.processName, proc_path, sizeof(rule.processName)-1);
    rule.temporaryPid = 0;      /* not implemented */
    rule.temporaryRule = false; /* not implemented */
    
    CFRelease(parameters);
    CFRelease(popup_options);
    CFRelease(radio_options);
    
    /* add new rule to driver */
    if (responseFlags & CFUserNotificationCheckBoxChecked(1) || responseFlags & CFUserNotificationCheckBoxChecked(2))
    {
        int kr = IOConnectCallMethod(driverConnection, kFlockFlockRequestAddClientRule, NULL, 0, &rule, sizeof(rule), NULL, NULL, NULL, NULL);
        if (kr == 0) {
            printf("new rule added successfully\n");
        } else {
            printf("error occured while adding new rule: %d\n", kr);
        }
        
        if (responseFlags & CFUserNotificationCheckBoxChecked(2)) {
            printf("writing new rule to .flockflockrc\n");
            write_new_rule(&rule);
        }
    }
    if (rule.ruleClass == kFlockFlockPolicyClassWhitelistAllMatching)
        return 0;
    
    return EACCES;
}

void *handle_policy_query(void *ptr)
{
    struct policy_query_msg *message = ptr;
    struct policy_response response;
    
#ifdef DEBUG
    printf("received policy query for pid %d target %s\n", message->query.pid, message->query.path);
#endif
    pthread_mutex_lock(&prompt_lock);
    memset(&response, 0, sizeof(struct policy_response));
    response.security_token = message->query.security_token;
    response.pid = message->query.pid;
    response.response_type = message->query.query_type;
    response.response = prompt_user_response(&message->query);
    
    pthread_mutex_lock(&lock);
    IOConnectCallMethod(driverConnection, kFlockFlockRequestPolicyResponse, NULL, 0, &response, sizeof(struct policy_response), NULL, NULL, NULL, NULL);
    pthread_mutex_unlock(&lock);
    pthread_mutex_unlock(&prompt_lock);
    
    free(ptr);
    pthread_exit(0);
    return(NULL);
}

void notification_callback(CFMachPortRef unusedport, void *voidmessage, CFIndex size, void *info)
{
    struct policy_query_msg *message = (struct policy_query_msg *)voidmessage;

    if (message->query.query_type == FFQ_ACCESS) {
        struct policy_query_msg *dup = malloc(sizeof(struct policy_query_msg));
        memcpy(dup, message, sizeof(struct policy_query_msg));
        pthread_t thread;
        pthread_create(&thread, NULL, handle_policy_query, dup);
        pthread_detach(thread);
    } else {
        printf("unknown notification arrived... oh noes!\n");
    }
}

int start_driver_comms() {
    io_iterator_t iter = 0;
    io_service_t service = 0;
    kern_return_t kr;
    CFMachPortRef notification_port;
    CFRunLoopSourceRef notification_loop;
    CFMachPortContext context;
    
    CFDictionaryRef matchDict = IOServiceMatching(DRIVER);
    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iter);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "IOServiceGetMatchingServices failed on error %d\n", kr);
        return E_FAIL;
    }
    
    if ((service = IOIteratorNext(iter)) != 0)
    {
        task_port_t owningTask = mach_task_self();
        CFStringRef className;
        uint32_t type = 0;
        kern_return_t kr;
        io_name_t name;
        
        className = IOObjectCopyClass(service);
        IORegistryEntryGetName(service, name);
        
        fprintf(stderr, "found driver '%s'\n", name);
        
        kr = IOServiceOpen(service, owningTask, type, &driverConnection);
        if (kr == KERN_SUCCESS) {
            CFStringRef str;
            char pid[16];
            int r;
            
            fprintf(stderr, "connected to driver %s\n", DRIVER);
            fprintf(stderr, "sending configuration\n");
            r = send_configuration(driverConnection);
            snprintf(pid, sizeof(pid), "%d", getpid());
            str = CFStringCreateWithCStringNoCopy(NULL, pid, kCFStringEncodingUTF8, NULL);
            IORegistryEntrySetCFProperty(service, CFSTR("pid"), str);
            
            if (r == 0) {
                context.version = 0;
                context.info = &driverConnection;
                context.retain = NULL;
                context.release = NULL;
                context.copyDescription = NULL;
                
                fprintf(stderr, "assigning notiication port\n");
                notification_port = CFMachPortCreate(NULL, notification_callback, &context, NULL);
                notification_loop = CFMachPortCreateRunLoopSource(NULL, notification_port, 0);
                mach_port_t port = CFMachPortGetPort(notification_port);
                IOConnectSetNotificationPort(driverConnection, 0, port, 0);
                
                fprintf(stderr, "starting filter\n");
                start_filter(driverConnection);
                
                fprintf(stderr, "waiting for notifications\n");
                CFRunLoopAddSource(CFRunLoopGetCurrent(), notification_loop, kCFRunLoopDefaultMode);
                CFRunLoopRun();
            }
        }
        
        fprintf(stderr, "closing connection to %s\n", DRIVER);
        IOServiceClose(service);
    } else {
        fprintf(stderr, "IOServiceOpen failed on error %d\n", kr);
    }
    
    IOObjectRelease(service);
    IOObjectRelease(iter);
    return 0;
}


int main(int argc, char *argv[]) {
    static struct termios oldt, newt;
    bool run = true;
    
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON);
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    pthread_mutex_init(&lock, NULL);
    pthread_mutex_init(&prompt_lock, NULL);
    atexit(stop);
    while(run) {
        start_driver_comms();
        sleep(5);
    }
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
    pthread_mutex_destroy(&lock);
    pthread_mutex_destroy(&prompt_lock);
}
