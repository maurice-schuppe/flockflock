//
//  FlockFlockClient.hpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOLib.h>
#include "FlockFlock.hpp"
#include "FlockFlockClientShared.h"

#ifndef FlockFlockClient_hpp
#define FlockFlockClient_hpp

class com_zdziarski_driver_FlockFlockClient : public IOUserClient
{
    OSDeclareDefaultStructors(com_zdziarski_driver_FlockFlockClient)
    
private:
    task_t m_task;
    bool m_taskIsAdmin;
    com_zdziarski_driver_FlockFlock *m_driver;
    
public:
    virtual bool initWithTask(task_t owningTask, void *securityToken, UInt32 type, OSDictionary *properties) override;
    virtual bool start(IOService *provider) override;
    virtual IOReturn clientClose(void) override;
    virtual void stop(IOService *provider) override;
    virtual void free(void) override;
    virtual IOReturn registerNotificationPort(mach_port_t port, UInt32 type, io_user_reference_t refCon) override;

    
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args, IOExternalMethodDispatch *dispatch,
                            OSObject *target, void *reference) override;
    
protected:
    static const IOExternalMethodDispatch sMethods[kFlockFlockRequestMethodCount];

    static IOReturn sClearConfiguration(OSObject *target, void *reference, IOExternalMethodArguments *args);
    static IOReturn sAddClientPolicy(OSObject *target, void *reference, IOExternalMethodArguments *args);
    static IOReturn sStartFilter(OSObject *target, void *reference, IOExternalMethodArguments *args);
    static IOReturn sStopFilter(OSObject *target, void *reference, IOExternalMethodArguments *args);
    static IOReturn sRespond(OSObject *target, void *reference, IOExternalMethodArguments *args);
};

#endif /* FlockFlockClient_hpp */
