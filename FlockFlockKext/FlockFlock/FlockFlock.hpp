//
//  FlockFlock.hpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#ifndef __FLOCKFLOCK_HPP_
#define __FLOCKFLOCK_HPP_

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/kern_event.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <security/mac_framework.h>
#include "FlockFlockClientShared.h"

struct mach_query_context
{
    IOLock *policy_lock, *reply_lock;
    struct policy_query_msg message;
    struct policy_response response;
    uint32_t security_token;
};

class com_zdziarski_driver_FlockFlock : public IOService
{
    OSDeclareDefaultStructors(com_zdziarski_driver_FlockFlock)
    
public:
    virtual bool init(OSDictionary *dictionary = NULL) override;
    virtual IOService *probe(IOService *provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free(void) override;
    virtual IOReturn setProperties(OSObject* properties) override;
    
    /* MAC policy methods and static hooks */
    static int ff_vnode_check_exec_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);
    int ff_vnode_check_exec(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);
    static int ff_vnode_check_open_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
    int ff_vnode_check_open(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
    static int ff_get_agent_pid_static(OSObject *provider);
    
    /* IOUserClient methods */
    bool startFilter();
    bool stopFilter();
    void clearMachPort();
    void clearAllRules();
    bool setMachPort(mach_port_t port);
    kern_return_t addClientPolicy(FlockFlockClientPolicy policy);

private:
    bool startProcessMonitor();
    bool stopProcessMonitor();

    bool initQueryContext(mach_query_context *context);
    void destroyQueryContext(mach_query_context *context);

    int sendPolicyQuery(struct policy_query *query, struct mach_query_context *context);
    bool receivePolicyResponse(struct policy_response *response, struct mach_query_context *context);

public:
    mach_port_t notificationPort;
    struct mach_query_context policyContext;
    uint32_t userAgentPID;

private:
    bool filterActive, shouldStop;
    IOLock *lock;
    IOLock *portLock;
    FlockFlockPolicyHierarchy policyRoot;
    FlockFlockPolicy lastPolicyAdded;
    OSDictionary *taskPathTable;
    
    /* file access policy */
    mac_policy_handle_t policyHandle;
    struct mac_policy_ops policyOps;
    struct mac_policy_conf policyConf;
    
    /* exec policy; we watch processes even when filtering isn't active */
    mac_policy_handle_t execHandle;
    struct mac_policy_ops execOps;
    struct mac_policy_conf execConf;
    
};

#endif