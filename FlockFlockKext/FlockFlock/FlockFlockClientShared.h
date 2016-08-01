//
//  FlockFlockClientShared.h
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#ifndef FlockFlockClientShared_h
#define FlockFlockClientShared_h

#define DRIVER "com_zdziarski_driver_FlockFlock"

enum FlockFlockRequestCode {
    kFlockFlockRequestClearConfiguration,
    kFlockFlockRequestAddClientRule,
    kFlockFlockRequestStartFilter,
    kFlockFlockRequestStopFilter,
    kFlockFlockRequestPolicyResponse,
    
    kFlockFlockRequestMethodCount
};

enum FlockFlockPolicyType {
    kFlockFlockPolicyTypePathPrefix,
    kFlockFlockPolicyTypeFilePath,
    kFlockFlockPolicyTypePathSuffix,
    
    kFlockFlockPolicyTypeCount
};

enum FlockFlockPolicyClass {
    kFlockFlockPolicyClassWhitelistAllMatching,
    kFlockFlockPolicyClassBlacklistAllMatching,
    kFlockFlockPolicyClassWhitelistAllNotMatching,
    kFlockFlockPolicyClassBlacklistAllNotMatching,
    
    kFlockFlockPolicyClassCount
};

typedef struct _FlockFlockClientPolicy {
    enum FlockFlockPolicyClass ruleClass;
    enum FlockFlockPolicyType ruleType;
    char processName[PATH_MAX];
    char rulePath[PATH_MAX];
    int32_t temporaryRule;
    int32_t temporaryPid;
} *FlockFlockClientPolicy;

typedef struct _FlockFlockPolicy {
    struct _FlockFlockClientPolicy data;
    struct _FlockFlockPolicy *next;
} *FlockFlockPolicy;

typedef FlockFlockPolicy FlockFlockPolicyHierarchy;

#define FFQ_ACCESS  0x0100

struct policy_query {
    pid_t pid;
    char path[PATH_MAX];
    uint32_t security_token;
    uint32_t query_type;
};

struct policy_response {
    pid_t pid;
    char path[PATH_MAX];
    uint32_t security_token;
    uint32_t response;
    uint32_t response_type;
};

struct policy_query_msg
{
    mach_msg_header_t header;
    struct policy_query query;
};

#endif /* FlockFlockClientShared_h */
