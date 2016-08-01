//
//  FlockFlock.cpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include "FlockFlock.hpp"

#define super IOService
OSDefineMetaClassAndStructors(com_zdziarski_driver_FlockFlock, IOService);

#define KMOD_PATH "/Library/Extensions/FlockFlock.kext"
#define SUPPORT_PATH "/Library/Application Support/FlockFlock"
#define LAUNCHD_PATH "/Library/LaunchDaemons/com.zdziarski.FlockFlock.plist"
#define LAUNCHD_AGENT "com.zdziarski.FlockFlockUserAgent.plist"
#define CONFIG "/.flockflockrc"

static OSObject *com_zdziarski_driver_FlockFlock_provider;

extern "C" {
    int _mac_policy_register_internal(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep);
    int _mac_policy_unregister_internal(mac_policy_handle_t handlep);
}

static int _ff_vnode_check_exec_internal(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
}

static int _ff_vnode_check_open_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_open_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, acc_mode);
}

/* defend against attacks to myself */
int _ff_eval_vnode(struct vnode *vp)
{
    char target_path[MAXPATHLEN];
    int target_len = MAXPATHLEN;
    int ret = 0;
    char proc_name[MAXPATHLEN];
    
    if (!vp)
        return 0;
    
    if (! vn_getpath(vp, target_path, &target_len))
    {
        target_path[MAXPATHLEN-1] = 0;
        target_len = (int)strlen(target_path);
    
        proc_selfname(proc_name, MAXPATHLEN);
        printf("_ff_eval_vnode evaluating op for %s[%d] %s\n", proc_name, proc_selfpid(), target_path);
        
        if (!strncmp(target_path, KMOD_PATH, strlen(KMOD_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, SUPPORT_PATH, strlen(SUPPORT_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_PATH, strlen(LAUNCHD_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(LAUNCHD_AGENT)), LAUNCHD_AGENT, strlen(LAUNCHD_AGENT)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(CONFIG)), CONFIG, strlen(CONFIG)))
            ret = EACCES;
    }
    
    if (ret == EACCES) {
        printf("_ff_eval_vnode: denying operation target path %s\n", target_path);
    }
    return ret;
}

int _ff_vnode_check_unlink_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_write_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_rename_from_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_truncate_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_setowner_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, uid_t uid, gid_t gid)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_setmode_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, mode_t mode)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

bool com_zdziarski_driver_FlockFlock::initQueryContext(mach_query_context *context) {
    context->policy_lock = IOLockAlloc();
    context->reply_lock  = IOLockAlloc();
    return true;
}

void com_zdziarski_driver_FlockFlock::destroyQueryContext(mach_query_context *context) {
    IOLog("FlockFlock::destroyQueryContext: waiting for lock");
    IOLockLock(context->policy_lock);
    IOLockLock(context->reply_lock);
    
    IOLog("FlockFlock::destroyQueryContext: destroying locks");
    IOLockFree(context->policy_lock);
    IOLockFree(context->reply_lock);
}

bool com_zdziarski_driver_FlockFlock::init(OSDictionary *dict)
{
    bool res = super::init(dict);
    if (!res)
        return(res);
    
    IOLog("FlockFlock::init\n");

    com_zdziarski_driver_FlockFlock_provider = this;
    notificationPort   = MACH_PORT_NULL;
    lastPolicyAdded    = NULL;
    policyRoot         = NULL;
    filterActive       = false;
    shouldStop         = false;
    userAgentPID       = 0;
 
    taskPathTable = new OSDictionary;
    taskPathTable->initWithCapacity(32767); 
    
    lock     = IOLockAlloc();
    portLock = IOLockAlloc();
    
    initQueryContext(&policyContext);
    
    setProperty("IOUserClientClass", "com_zdziarski_driver_FlockFlockClient");
    return res;
}

IOService *com_zdziarski_driver_FlockFlock::probe(IOService *provider, SInt32* score)
{
    IOLog("IOKitTest::probe\n");

    IOService *res = super::probe(provider, score);
    return res;
}

bool com_zdziarski_driver_FlockFlock::start(IOService *provider)
{
    IOLog("IOKitTest::start\n");

    bool res = super::start(provider);
    if (res != true) {
        IOLog("FlockFlock::start failed: IOService::start failed\n");
        return res;
    }

    super::registerService();
    IOLog("FlockFlock::start successful\n");
    startProcessMonitor();

    return true;
}

bool com_zdziarski_driver_FlockFlock::startProcessMonitor()
{
    bool success = false;
    
    execHandle = { 0 };
    execOps = {
        .mpo_vnode_check_exec   = _ff_vnode_check_exec_internal,
        .mpo_vnode_check_unlink = _ff_vnode_check_unlink_internal,
//        .mpo_vnode_check_write  = _ff_vnode_check_write_internal,
        .mpo_vnode_check_setmode = _ff_vnode_check_setmode_internal,
        .mpo_vnode_check_setowner = _ff_vnode_check_setowner_internal,
//        .mpo_vnode_check_truncate    = _ff_vnode_check_truncate_internal,
        .mpo_vnode_check_rename_from = _ff_vnode_check_rename_from_internal
    };
    execConf = {
        .mpc_name            = "FF Process Monitor and Defenses",
        .mpc_fullname        = "FlockFlock Kernel-Mode Process Monitor and Defenses",
        .mpc_labelnames      = NULL,
        .mpc_labelname_count = 0,
        .mpc_ops             = &execOps,
        .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK, /* disable MPC_LOADTIME_FLAG_UNLOADOK to prevent unloading */
        .mpc_field_off       = NULL,
        .mpc_runtime_flags   = 0,
        .mpc_list            = NULL,
        .mpc_data            = NULL
    };
    
    int mpr = _mac_policy_register_internal(&execConf, &execHandle);
    if (!mpr ) {
        success = true;
        IOLog("FlockFlock::startProcessMonitor: process monitor started successfully\n");
    } else {
        IOLog("FlockFlock::startProcessMonitor: an error occured while starting the process monitor: %d\n", mpr);
    }
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopProcessMonitor()
{
    bool success = false;
    kern_return_t kr = _mac_policy_unregister_internal(execHandle);
    if (kr == KERN_SUCCESS) {
        success = true;
        IOLog("FlockFlock::stopFilter: process monitor stopped successfully\n");
    } else {
        IOLog("FlockFlock::stopFilter: an error occured while stopping the process monitor: %d\n", kr);
    }
    return success;
}

bool com_zdziarski_driver_FlockFlock::startFilter()
{
    bool success = false;
    
    IOLockLock(lock);
    if (filterActive == false) {
        policyHandle = { 0 };
        policyOps = {
            .mpo_vnode_check_open = _ff_vnode_check_open_internal
        };
        policyConf = {
            .mpc_name            = "FF File Monitor",
            .mpc_fullname        = "FlockFlock Kernel-Mode File Monitor",
            .mpc_labelnames      = NULL,
            .mpc_labelname_count = 0,
            .mpc_ops             = &policyOps,
            .mpc_loadtime_flags  = 0, /* disable MPC_LOADTIME_FLAG_UNLOADOK to prevent unloading 
                                       *
                                       * NOTE: setting this to 0 CAUSES A KERNEL PANIC AND REBOOT if the module is
                                       *     unloaded. This is how we defend against malware unloading it. */
            .mpc_field_off       = NULL,
            .mpc_runtime_flags   = 0,
            .mpc_list            = NULL,
            .mpc_data            = NULL
        };

        int mpr = _mac_policy_register_internal(&policyConf, &policyHandle);
        if (!mpr ) {
            filterActive = true;
            success = true;
            IOLog("FlockFlock::startFilter: filter started successfully\n");
        } else {
            IOLog("FlockFlock::startFilter: an error occured while starting the filter: %d\n", mpr);
        }
    }
    IOLockUnlock(lock);
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopFilter()
{
    bool success = false;
    IOLockLock(lock);
    if (filterActive == true) {
        kern_return_t kr = _mac_policy_unregister_internal(policyHandle);
        if (kr == KERN_SUCCESS) {
            filterActive = false;
            success = true;
            IOLog("FlockFlock::stopFilter: filter stopped successfully\n");
        } else {
            IOLog("FlockFlock::stopFilter: an error occured while stopping the filter: %d\n", kr);
        }
    }
    IOLockUnlock(lock);
    return success;
}

void com_zdziarski_driver_FlockFlock::clearAllRules()
{
    IOLog("IOKitTest::clearAllRules\n");

    IOLockLock(lock);
    FlockFlockPolicy rule = policyRoot;
    while(rule) {
        FlockFlockPolicy next = rule->next;
        IOFree(rule, sizeof(*rule));
        rule = next;
    }
    policyRoot = NULL;
    lastPolicyAdded = NULL;
    IOLockUnlock(lock);
}

kern_return_t com_zdziarski_driver_FlockFlock::addClientPolicy(FlockFlockClientPolicy clientRule)
{
    FlockFlockPolicy rule;
    
    IOLog("IOKitTest::addClientPolicy\n");

    if (! clientRule)
        return KERN_INVALID_VALUE;
    
    IOLockLock(lock);
    
    rule = (FlockFlockPolicy) IOMalloc(sizeof(struct _FlockFlockPolicy));
    if (!rule) {
        IOLockUnlock(lock);
        return KERN_MEMORY_ERROR;
    }
    bcopy(clientRule, &rule->data, sizeof(*clientRule));
    rule->next = NULL;
    
    if (lastPolicyAdded == NULL)
        policyRoot = rule;
    else
        lastPolicyAdded->next = rule;
    
    lastPolicyAdded = rule;

    IOLockUnlock(lock);
    return KERN_SUCCESS;
}

bool com_zdziarski_driver_FlockFlock::setMachPort(mach_port_t port)
{
    bool ret = false;
    IOLockLock(portLock);
    if (notificationPort == MACH_PORT_NULL) {
        notificationPort = port;
        ret = true;
    }
    IOLockUnlock(portLock);
    return ret;
}

void com_zdziarski_driver_FlockFlock::clearMachPort() {
    IOLockLock(portLock);
    notificationPort = MACH_PORT_NULL;
    IOLockUnlock(portLock);
}

IOReturn com_zdziarski_driver_FlockFlock::setProperties(OSObject* properties)
{
    OSDictionary *propertyDict;
    
    propertyDict = OSDynamicCast(OSDictionary, properties);
    if (propertyDict != NULL)
    {
        OSObject *theValue;
        OSString *theString;
        
        theValue = propertyDict->getObject("pid");
        theString = OSDynamicCast(OSString, theValue);
        userAgentPID = (uint32_t)strtol(theString->getCStringNoCopy(), NULL, 0);
        if (userAgentPID) {
            printf("FlockFlock::setProperties: set pid to %d\n", userAgentPID);
            return kIOReturnSuccess;
        }
    }
    
    return kIOReturnUnsupported;
}

bool com_zdziarski_driver_FlockFlock::receivePolicyResponse(struct policy_response *response, struct mach_query_context *context)
{
    bool success = false;
    bool lock = IOLockTryLock(context->reply_lock);
    
    while(lock == false && shouldStop == false) {
        IOSleep(1000);
        lock = IOLockTryLock(context->reply_lock);
    }
    
    if (lock == false) { /* filter was shut down */
        IOLockUnlock(context->reply_lock);
        IOLockUnlock(context->policy_lock);
        return false;
    }
    
    // IOLockLock(context->reply_lock);
    if (context->security_token == context->response.security_token) {
        bcopy(&context->response, response, sizeof(struct policy_response));
        success = true;
    } else {
        printf("FlockFlock::receive_policy_response: policy response failed (invalid security token)\n");
    }
    
    IOLockUnlock(context->policy_lock);
    IOLockUnlock(context->reply_lock);
    return true;
}

int com_zdziarski_driver_FlockFlock::sendPolicyQuery(struct policy_query *query, struct mach_query_context *context) {
    int ret;
    
    context->message.header.msgh_remote_port = notificationPort;
    context->message.header.msgh_local_port = MACH_PORT_NULL;
    context->message.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    context->message.header.msgh_size = sizeof(context->message);
    context->message.header.msgh_id = 0;
    
    query->security_token = random();
    bcopy(query, &context->message.query, sizeof(struct policy_query));
    
    IOLockLock(context->policy_lock);
    IOLockLock(context->reply_lock);
    
    ret = mach_msg_send_from_kernel(&context->message.header, sizeof(context->message));
    if (ret) {
        IOLockUnlock(context->policy_lock);
        IOLockUnlock(context->reply_lock);
        return ret;
    }
    
    context->security_token = query->security_token;
    return ret;
}

int com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->userAgentPID;
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_exec(cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_exec(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    char proc_path[MAXPATHLEN];
    int pid = proc_selfpid();
    int proc_len = MAXPATHLEN;
    int ret;
    
    printf("ff_vnode_check_exec: looking up process path for pid %d\n", pid);

    ret = vn_getpath(vp, proc_path, &proc_len); /* path to proc binary */
    if (ret != 0) {
        printf("ff_vnode_check_exec: lookup failed for pid %d, error %d, looking up script path\n", pid, ret);
        ret = vn_getpath(scriptvp, proc_path, &proc_len); /* path to proc script */
    }
    
    if (ret == 0) {
        OSString *processPath = OSString::withCString(proc_path);
        char pidString[16];
        proc_path[MAXPATHLEN-1] = 0;
        
        printf("ff_vnode_check_exec: process path for pid %d is %s\n", pid, proc_path);

        snprintf(pidString, sizeof(pidString), "%d", pid);
        taskPathTable->setObject(pidString, processPath);
    } else {
        printf("ff_vnode_check_exec: lookup failed for pid %d, error %d\n", pid, ret);
    }
    
    return 0;
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_open_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_open(cred, vp, label, acc_mode);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_open(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    bool blacklisted = false, whitelisted = false;
    struct policy_response response;
    char target[PATH_MAX];
    char proc_path[PATH_MAX];
    size_t target_len = 0, proc_len = 0;
    int buflen = PATH_MAX;
    int pid = proc_selfpid();
    char pidString[16];
    int ret = EACCES;
    OSString *processPath;
    
    if (vp == NULL)         /* something happened */
        return 0;
    if (vnode_isdir(vp))    /* always allow directories, we only work with files */
        return 0;
    
    if (! vn_getpath(vp, target, &buflen))  /* path to target (file) */
        target_len = strlen(target);
    target[PATH_MAX-1] = 0;
    
    if (userAgentPID == pid) {
        printf("allowing user agent pid access to %s\n", target);
        return 0;
    }
    
    if (!strncmp(target, "/dev/", 5)) /* allow all /dev access */
        return 0;
    
    snprintf(pidString, sizeof(pidString), "%d", pid);
    processPath = (OSString *)taskPathTable->getObject(pidString);
    if (processPath) {
        strncpy(proc_path, processPath->getCStringNoCopy(), PATH_MAX);
        proc_len = strlen(proc_path);
        printf("ff_vnode_check_open: process path for pid %d is %s\n", pid, proc_path);
    } else {
        printf("ff_vnode_check_open: failed to locate process path for pid %d\n", pid);
        return 0;
    }
    
    FlockFlockPolicy rule = policyRoot;
    while(rule) {
        int match = 1;
        size_t rpath_len = strlen(rule->data.rulePath);
        
        /* temporary rules must match the pid of the current operation */
        if (rule->data.temporaryRule && rule->data.temporaryPid != pid)
            match = 0;
        
        /* rule out any process-specific rules that don't match */
        if (rule->data.processName[0]) {
            size_t ppath_len = strlen(rule->data.processName);
            if (rule->data.processName[ppath_len-1] == '/') { /* directory prefix */
                if (strncmp(proc_path, rule->data.processName, ppath_len)) {
                    match = 0;
                }
            } else if (strcmp(proc_path, rule->data.processName)) { /* full path */
                match = 0;
            }
        }
        
        /* rule out any path rules that don't match */
        if (rpath_len) {
            switch(rule->data.ruleType) {
                case(kFlockFlockPolicyTypePathPrefix):
                    if (strncasecmp(rule->data.rulePath, target, strlen(rule->data.rulePath)))
                        match = 0;
                    break;
                case(kFlockFlockPolicyTypeFilePath):
                    if (rule->data.rulePath[rpath_len-1] == '/') { /* directory prefix */
                        if (strncmp(target, rule->data.rulePath, rpath_len)) {
                            match = 0;
                        }
                        if (target_len > rpath_len) { /* don't apply to nested folders */
                            if (strchr(target + rpath_len, '/')) {
                                match = 0;
                            }
                        }
                    } else if (strcasecmp(rule->data.rulePath, target)) { /* full path */
                        match = 0;
                    }
                    break;
                case(kFlockFlockPolicyTypePathSuffix):
                    if (target_len <= rpath_len)
                        match = 0;
                    if (strcasecmp(target + (target_len - rpath_len), rule->data.rulePath))
                        match = 0;
                    break;
                default:
                    break;
            }
        }
        
        switch(rule->data.ruleClass) {
            case(kFlockFlockPolicyClassBlacklistAllMatching):
                if (match)
                    blacklisted = true;
                break;
            case(kFlockFlockPolicyClassWhitelistAllMatching):
                if (match)
                    whitelisted = true;
                break;
            case(kFlockFlockPolicyClassBlacklistAllNotMatching):
                if (! match)
                    blacklisted = true;
                break;
            case(kFlockFlockPolicyClassWhitelistAllNotMatching):
                if (! match)
                    whitelisted = true;
            default:
                break;
                
        }
        rule = rule->next;
    }
    
    if (whitelisted == true) {
        ret = 0;
        //printf("FlockFlock::ff_vnode_check_open: allow open of %s by pid %d (%s) wht %d blk %d\n", target, pid, proc_path, whitelisted, blacklisted);
    } else if (blacklisted == true) {
        printf("FlockFlock::ff_vnode_check_open: deny open of %s by pid %d (%s) wht %d blk %d\n", target, pid, proc_path, whitelisted, blacklisted);
    } else { /* ask user */
        struct policy_query query;
        query.pid = pid;
        query.query_type = FFQ_ACCESS;
        bcopy(target, query.path, target_len+1);
        
        printf("FlockFlock::ff_vnode_check_open: ask open of %s by pid %d (%s) wht %d blk %d\n", target, pid, proc_path, whitelisted, blacklisted);
        
        if (sendPolicyQuery(&query, &policyContext) == 0) {
            printf("FlockFlock::ff_node_check_option: sent policy query successfully, waiting for reply\n");
            bool success = receivePolicyResponse(&response, &policyContext);
            if (success) {
                ret = response.response;
            }
        } else {
            printf("FlockFlock::ff_vnode_check_open: user agent is unavailable to prompt user, denying access\n");
        }
    }
    
    return ret;
}

void com_zdziarski_driver_FlockFlock::stop(IOService *provider)
{
    bool active;
    IOLog("FlockFlock::stop\n");
    
    shouldStop = true;
    
    IOLockLock(lock);
    active = filterActive;
    IOLockUnlock(lock);
    
    stopProcessMonitor();

    if (active == true) {
        stopFilter();
    }
        
    super::stop(provider);
}

void com_zdziarski_driver_FlockFlock::free(void)
{
    IOLog("IOKitTest::free\n");
    clearAllRules();
    IOLockFree(lock);
    IOLockFree(portLock);
    
    destroyQueryContext(&policyContext);
    taskPathTable->free();

    super::free();
}
