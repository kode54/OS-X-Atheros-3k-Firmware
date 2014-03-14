/* IOath3kfrmwr class */
#ifndef __IOATH3KFRMWR__
#define __IOATH3KFRMWR__

#ifdef DEBUG_MSG
#define DEBUG_LOG(args...)  IOLog(args)
#else
#define DEBUG_LOG(args...)
#endif

#include <IOKit/usb/IOUSBDevice.h>

#define EXPORT __attribute__((visibility("default")))

#define local_IOath3kfrmwr org_rehabman_IOath3kfrmwr

class EXPORT local_IOath3kfrmwr : public IOService
{
    typedef IOService super;
    OSDeclareDefaultStructors(org_rehabman_IOath3kfrmwr)
    
    bool load_firmware(IOUSBInterface * intf, unsigned char const* firmware, size_t firmware_size);
    bool get_state(IOUSBInterface * intf, unsigned char * state);
    
    struct ath3k_version {
        uint32_t    rom_version;
        uint32_t    build_version;
        uint32_t    ram_version;
        uint8_t     ref_clock;
        uint8_t     reserved[0x07];
    };

    bool get_version(IOUSBInterface * intf, struct ath3k_version * version);

    bool switch_pid(IOUSBInterface * intf);
    bool set_normal_mode(IOUSBInterface * intf);
    bool load_patch(IOUSBInterface * intf);
    bool load_syscfg(IOUSBInterface * intf);
    
protected:
    IOUSBDevice * pUsbDev;
        
public:
#ifdef DEBUG
    // this is from the IORegistryEntry - no provider yet
    virtual bool 	init(OSDictionary *propTable);
    
    // IOKit methods. These methods are defines in <IOKit/IOService.h>
    virtual IOService* probe(IOService *provider, SInt32 *score );
    
    virtual bool attach(IOService *provider);
    virtual void detach(IOService *provider);
#endif
    
    virtual bool start(IOService *provider);
#ifdef DEBUG
    virtual void stop(IOService *provider);
    
    virtual bool handleOpen(IOService *forClient, IOOptionBits options = 0, void *arg = 0 );
    virtual void handleClose(IOService *forClient, IOOptionBits options = 0 );
    
    virtual IOReturn message(UInt32 type, IOService *provider, void *argument);
    
    virtual bool terminate(IOOptionBits options = 0);
    virtual bool finalize(IOOptionBits options);
#endif
};

#endif //__IOATH3KFRMWR__ 

