/* Disclaimer:
 This code is loosely based on the template of the class 
 in AnchorUSB Driver example from IOUSBFamily, 
 Open Source by Apple http://www.opensource.apple.com
 
 For information on driver matching for USB devices, see: 
 http://developer.apple.com/qa/qa2001/qa1076.html

 */
#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/usb/IOUSBInterface.h>

#include "IOath3kfrmwr.h"

#ifndef IOATH3KNULL
#include "ath3k-1fw.h"

// Ath3012 stuff
#include "AthrBT.h"
#include "ramps.h"
#endif

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - //

#define USB_REQ_DFU_DNLOAD	1

#define ATH3K_DNLOAD				0x01
#define ATH3K_GETSTATE				0x05
#define ATH3K_SET_NORMAL_MODE		0x07
#define ATH3K_GETVERSION			0x09
#define USB_REG_SWITCH_VID_PID		0x0a

#define ATH3K_MODE_MASK				0x3F
#define ATH3K_NORMAL_MODE			0x0E

#define ATH3K_PATCH_UPDATE			0x80
#define ATH3K_SYSCFG_UPDATE			0x40

#define ATH3K_XTAL_FREQ_26M			0x00
#define ATH3K_XTAL_FREQ_40M			0x01
#define ATH3K_XTAL_FREQ_19P2		0x02

//rehabman:
// Note: mac4mat's original had this BULK_SIZE at 4096.  Turns out sending
// the firmware 4k at a time doesn't quite work in SL. And it seems
// sending it 1k at a time works in SL, Lion, and ML.

#define BULK_SIZE	1024

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - //

OSDefineMetaClassAndStructors(org_rehabman_IOath3kfrmwr, IOService)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - //

#ifdef DEBUG
bool local_IOath3kfrmwr::init(OSDictionary *propTable)
{
#ifdef DEBUG
    IOLog("org_rehabman_IOath3kfrmwr(%p): init (https://github.com/RehabMan/OS-X-Atheros-3k-Firmware.git)\n", this);
#else
    IOLog("IOath3kfrmwr: init (https://github.com/RehabMan/OS-X-Atheros-3k-Firmware.git)\n");
#endif
    return (super::init(propTable));
}

IOService* local_IOath3kfrmwr::probe(IOService *provider, SInt32 *score)
{
    DEBUG_LOG("%s(%p)::probe\n", getName(), this);
    return super::probe(provider, score);			// this returns this
}

bool local_IOath3kfrmwr::attach(IOService *provider)
{
    // be careful when performing initialization in this method. It can be and
    // usually will be called mutliple 
    // times per instantiation
    DEBUG_LOG("%s(%p)::attach\n", getName(), this);
    return super::attach(provider);
}

void local_IOath3kfrmwr::detach(IOService *provider)
{
    // Like attach, this method may be called multiple times
    DEBUG_LOG("%s(%p)::detach\n", getName(), this);
    return super::detach(provider);
}
#endif // DEBUG

//
// load_firmware
// Send the main firmware block
//

bool local_IOath3kfrmwr::load_firmware(IOUSBInterface * intf, unsigned char const* firmware, size_t firmware_size)
{
    IOReturn 				err;

    // 2.3 Get the pipe for bulk endpoint 2 Out
    OSNumber* nPipe = OSDynamicCast(OSNumber, getProperty("PipeNumber"));
    if (!nPipe) {
        DEBUG_LOG("%s(%p)::load_firmware - PipeNumber not specified\n", getName(), this);
        return false;
    }
    IOUSBPipe * pipe = intf->GetPipeObj(nPipe->unsigned8BitValue());
    if (!pipe) {
        IOLog("%s(%p)::load_firmware - failed to find bulk out pipe %d\n", getName(), this, nPipe->unsigned8BitValue());
        return false;
    }
    
    /*  // TODO: Test the alternative way to do it:
     IOUSBFindEndpointRequest pipereq;
     pipereq.type = kUSBBulk;
     pipereq.direction = kUSBOut;
     pipereq.maxPacketSize = BULK_SIZE;
     pipereq.interval = 0;
     IOUSBPipe *pipe = intf->FindNextPipe(NULL, &pipereq);
     pipe = intf->FindNextPipe(pipe, &pipereq);
     if (!pipe) {
     DEBUG_LOG("%s(%p)::start - failed to find bulk out pipe 2\n", getName(), this);
     return false;
     }
     */
    
    size_t size = min(firmware_size, 20);
    
    // 3.0 Send request to Control Endpoint to initiate the firmware transfer
    IOUSBDevRequest ctlreq;
    ctlreq.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBVendor, kUSBDevice);
    ctlreq.bRequest = USB_REQ_DFU_DNLOAD;
    ctlreq.wValue = 0;
    ctlreq.wIndex = 0;
    ctlreq.wLength = size;
    ctlreq.pData = (void *) firmware;
    
#if 0  // Trying to troubleshoot the problem after Restart (with OSBundleRequired Root)
    for (int irep = 0; irep < 5; irep++) { // retry on error
        err = pUsbDev->DeviceRequest(&ctlreq); // (synchronous, will block)
        if (err)
            IOLog("%s(%p)::load_firmware - failed to initiate firmware transfer (%d), retrying (%d)\n", getName(), this, err, irep+1);
        else
            break;
    }
#else
    err = pUsbDev->DeviceRequest(&ctlreq); // (synchronous, will block)
#endif
    if (err) {
        IOLog("%s(%p)::load_firmware - failed to initiate firmware transfer (%d)\n", getName(), this, err);
        return false;
    }
    
    // 3.1 Create IOMemoryDescriptor for bulk transfers
    char buftmp[BULK_SIZE];
    IOMemoryDescriptor * membuf = IOMemoryDescriptor::withAddress(&buftmp, BULK_SIZE, kIODirectionNone);
    if (!membuf) {
        IOLog("%s(%p)::load_firmware - failed to map memory descriptor\n", getName(), this);
        return false;
    }
    err = membuf->prepare();
    if (err) {
        IOLog("%s(%p)::load_firmware - failed to prepare memory descriptor\n", getName(), this);
        return false;
    }
    
    // 3.2 Send the rest of firmware to the bulk pipe
    unsigned char const* buf = firmware + size;
    size = firmware_size - size;
    int ii = 1;
    while (size) {
        int to_send = size < BULK_SIZE ? (int)size : BULK_SIZE;
        
        memcpy(buftmp, buf, to_send);
        err = pipe->Write(membuf, 10000, 10000, to_send);
        if (err) {
            IOLog("%s(%p)::load_firmware - failed to write firmware to bulk pipe (err:%d, block:%d, to_send:%d)\n", getName(), this, err, ii, to_send);
            return false;
        }
        buf += to_send;
        size -= to_send;
        ii++;
    }
    
#ifdef DEBUG
    IOLog("%s(%p)::load_firmware: firmware was sent to bulk pipe\n", getName(), this);
#else
    IOLog("IOath3kfrmwr: firmware loaded successfully!\n");
#endif
    
    err = membuf->complete();
    if (err) {
        IOLog("%s(%p)::load_firmware - failed to complete memory descriptor\n", getName(), this);
        return false;
    }
    
    return true;
}

//
// get_state
// checks the current hardware state, needed by ath3012 devices
//
bool local_IOath3kfrmwr::get_state(IOUSBInterface * intf, unsigned char * state)
{
    IOReturn err;
    
    char buf;
    
    IOUSBDevRequest ctlreq;
    ctlreq.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    ctlreq.bRequest = ATH3K_GETSTATE;
    ctlreq.wValue = 0;
    ctlreq.wIndex = 0;
    ctlreq.wLength = sizeof(buf);
    ctlreq.pData = &buf;

    err = pUsbDev->DeviceRequest(&ctlreq); // (synchronous, will block)

    if ( err )
    {
        IOLog("%s(%p)::get_state - failed to read device state\n", getName(), this);
        return false;
    }
    
    *state = buf;
    
    return true;
}

//
// get_version
// retrieves the device version descriptor
//
bool local_IOath3kfrmwr::get_version(IOUSBInterface *intf, struct ath3k_version * version)
{
    IOReturn err;
    
    struct ath3k_version buf;
    
    IOUSBDevRequest ctlreq;
    ctlreq.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    ctlreq.bRequest = ATH3K_GETVERSION;
    ctlreq.wValue = 0;
    ctlreq.wIndex = 0;
    ctlreq.wLength = sizeof(buf);
    ctlreq.pData = &buf;
    
    err = pUsbDev->DeviceRequest(&ctlreq); // (synchronous, will block)
    
    if ( err )
    {
        IOLog("%s(%p)::get_version - failed to read device version\n", getName(), this);
        return false;
    }
    
    *version = buf;
    
    return true;
}

//
// switch_pid
// switches ath3012 device vid/pid
//
bool local_IOath3kfrmwr::switch_pid(IOUSBInterface *intf)
{
    IOReturn err;
    
    IOUSBDevRequest ctlreq;
    ctlreq.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    ctlreq.bRequest = USB_REG_SWITCH_VID_PID;
    ctlreq.wValue = 0;
    ctlreq.wIndex = 0;
    ctlreq.wLength = 0;
    ctlreq.pData = 0;
    
    err = pUsbDev->DeviceRequest(&ctlreq); // (synchronous, will block)
    
    if ( err )
    {
        IOLog("%s(%p)::switch_pid - failed to switch device pid\n", getName(), this);
        return false;
    }
 
    return true;
}

//
// set_normal_mode
// sets ath3012 device into normal mode
//
bool local_IOath3kfrmwr::set_normal_mode(IOUSBInterface *intf)
{
    bool ret;
	unsigned char fw_state;
    IOReturn err;
    
	ret = get_state(intf, &fw_state);
	if (!ret) {
        IOLog("%s(%p)::set_normal_mode - Can't get state to change to normal mode\n", getName(), this);
		return false;
	}
    
	if ((fw_state & ATH3K_MODE_MASK) == ATH3K_NORMAL_MODE) {
        IOLog("%s(%p)::set_normal_mode - firmware was already in normal mode\n", getName(), this);
		return true;
	}
    
    IOUSBDevRequest ctlreq;
    ctlreq.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    ctlreq.bRequest = ATH3K_SET_NORMAL_MODE;
    ctlreq.wValue = 0;
    ctlreq.wIndex = 0;
    ctlreq.wLength = 0;
    ctlreq.pData = 0;

    err = pUsbDev->DeviceRequest(&ctlreq);
    
    if ( err )
    {
        IOLog("%s(%p)::set_normal_mode - failed to change to normal mode\n", getName(), this);
        return false;
    }
    
    return true;
}

//
// load_patch
// loads an ath3012 firmware patch
//
bool local_IOath3kfrmwr::load_patch(IOUSBInterface *intf)
{
	unsigned char fw_state;
	struct ath3k_version fw_version, pt_version;
	int ret;
    
	ret = get_state(intf, &fw_state);
	if (!ret) {
        IOLog("%s(%p)::load_patch - can't get state to change to load ram patch\n", getName(), this);
		return false;
	}
    
	if (fw_state & ATH3K_PATCH_UPDATE) {
        IOLog("%s(%p)::load_patch - patch was already downloaded\n", getName(), this);
		return true;
	}
    
	ret = get_version(intf, &fw_version);
	if (!ret) {
        IOLog("%s(%p)::load_patch - can't get version to change to load ram patch\n", getName(), this);
		return false;
	}

    const unsigned char * firmware;
    size_t firmware_size;
    
    switch ( fw_version.rom_version )
    {
        case 0x01020001:
            firmware = firmware_0x01020001;
            firmware_size = sizeof(firmware_0x01020001);
            break;
            
        case 0x01020200:
            firmware = firmware_0x01020200;
            firmware_size = sizeof(firmware_0x01020200);
            break;
            
        case 0x01020201:
            firmware = firmware_0x01020201;
            firmware_size = sizeof(firmware_0x01020201);
            break;
            
        case 0x11020000:
            firmware = firmware_0x11020000;
            firmware_size = sizeof(firmware_0x11020000);
            break;
            
        case 0x31010000:
            firmware = firmware_0x31010000;
            firmware_size = sizeof(firmware_0x31010000);
            break;
            
        case 0x41020000:
            firmware = firmware_0x41020000;
            firmware_size = sizeof(firmware_0x41020000);
            break;
            
        default:
            IOLog("%s(%p)::load_patch - unknown rom version 0x%08x\n", getName(), this, fw_version.rom_version );
            return false;
    }
    
	pt_version.rom_version = *(uint32_t *)(firmware + firmware_size - 8);
	pt_version.build_version = *(uint32_t *)
    (firmware + firmware_size - 4);
    
	if ((pt_version.rom_version != fw_version.rom_version) ||
		(pt_version.build_version <= fw_version.build_version)) {
        IOLog("%s(%p)::load_patch - patch block version did not match with firmware\n", getName(), this);
        return false;
	}
    
	ret = load_firmware(intf, firmware, firmware_size);
    
	return ret;
}

//
// load_syscfg
// loads an ath3012 system configuration
//
bool local_IOath3kfrmwr::load_syscfg(IOUSBInterface *intf)
{
    bool ret;
	unsigned char fw_state;
	struct ath3k_version fw_version;
	int clk_value;
    
	ret = get_state(intf, &fw_state);
	if (!ret) {
        IOLog("%s(%p)::load_syscfg - can't get state to change to load configuration\n", getName(), this);
		return false;
	}
    
	ret = get_version(intf, &fw_version);
	if (!ret) {
        IOLog("%s(%p)::load_syscfg - can't get version to change to load ram patch\n", getName(), this);
		return false;
	}
    
	switch (fw_version.ref_clock) {
            
        case ATH3K_XTAL_FREQ_26M:
            clk_value = 26;
            break;
        case ATH3K_XTAL_FREQ_40M:
            clk_value = 40;
            break;
        case ATH3K_XTAL_FREQ_19P2:
            clk_value = 19;
            break;
        default:
            clk_value = 0;
            break;
	}
    
    const unsigned char * firmware = 0;
    size_t firmware_size = 0;
    
    switch (fw_version.rom_version)
    {
        case 0x01020001:
            switch (clk_value)
            {
                case 26:
                    firmware = ramps_0x01020001_26;
                    firmware_size = sizeof(ramps_0x01020001_26);
                    break;
            }
            break;
            
        case 0x01020200:
            switch (clk_value)
            {
                case 26:
                    firmware = ramps_0x01020200_26;
                    firmware_size = sizeof(ramps_0x01020200_26);
                    break;
                    
                case 40:
                    firmware = ramps_0x01020200_40;
                    firmware_size = sizeof(ramps_0x01020200_40);
                    break;
            }
            break;
            
        case 0x01020201:
            switch (clk_value)
            {
                case 26:
                    firmware = ramps_0x01020201_26;
                    firmware_size = sizeof(ramps_0x01020201_26);
                    break;
                    
                case 40:
                    firmware = ramps_0x01020201_40;
                    firmware_size = sizeof(ramps_0x01020201_40);
                    break;
            }
            break;
            
        case 0x11020000:
            switch (clk_value)
            {
                case 40:
                    firmware = ramps_0x11020000_40;
                    firmware_size = sizeof(ramps_0x11020000_40);
                    break;
            }
            break;
            
        case 0x31010000:
            switch (clk_value)
            {
                case 40:
                    firmware = ramps_0x31010000_40;
                    firmware_size = sizeof(ramps_0x31010000_40);
                    break;
            }
            
        case 0x41020000:
            switch (clk_value)
            {
                case 40:
                    firmware = ramps_0x41020000_40;
                    firmware_size = sizeof(ramps_0x41020000_40);
                    break;
            }
            break;
    }
    
    if ( !firmware || !firmware_size )
    {
        IOLog("%s(%p)::load_syscfg - unknown firmware version and base clock combination 0x%08x %d\n", getName(), this, fw_version.rom_version, clk_value);
        return false;
    }

    ret = load_firmware(intf, firmware, firmware_size);
    
	return ret;
}

//
// start
// when this method is called, I have been selected as the driver for this device.
// I can still return false to allow a different driver to load
//
bool local_IOath3kfrmwr::start(IOService *provider)
{
#ifdef DEBUG
    IOLog("%s(%p)::start - Version 1.2.0 starting\n", getName(), this);
#else
    IOLog("IOath3kfrmwr: Version 1.2.0 starting\n");
#endif
    
    IOReturn 				err;
    const IOUSBConfigurationDescriptor *cd;
    
    // Do all the work here, on an IOKit matching thread.
    
    // 0.1 Get my USB Device
    DEBUG_LOG("%s(%p)::start!\n", getName(), this);
    pUsbDev = OSDynamicCast(IOUSBDevice, provider);
    if(!pUsbDev) 
    {
        IOLog("%s(%p)::start - Provider isn't a USB device!!!\n", getName(), this);
        return false;
    }

    // 0.2 Reset the device
    err = pUsbDev->ResetDevice();
    if (err)
    {
        IOLog("%s(%p)::start - failed to reset the device\n", getName(), this);
        return false;
    }
    DEBUG_LOG("%s(%p)::start: device reset\n", getName(), this);
    
    // 0.3 Find the first config/interface
    int numconf = 0;
    if ((numconf = pUsbDev->GetNumConfigurations()) < 1)
    {
        IOLog("%s(%p)::start - no composite configurations\n", getName(), this);
        return false;
    }
    DEBUG_LOG("%s(%p)::start: num configurations %d\n", getName(), this, numconf);
        
    // 0.4 Get first config descriptor
    cd = pUsbDev->GetFullConfigurationDescriptor(0);
    if (!cd)
    {
        IOLog("%s(%p)::start - no config descriptor\n", getName(), this);
        return false;
    }
	
    // 1.0 Open the USB device
    if (!pUsbDev->open(this))
    {
        IOLog("%s(%p)::start - unable to open device for configuration\n", getName(), this);
        return false;
    }
    
    // 1.1 Set the configuration to the first config
    err = pUsbDev->SetConfiguration(this, cd->bConfigurationValue, true);
    if (err)
    {
        IOLog("%s(%p)::start - unable to set the configuration\n", getName(), this);
        pUsbDev->close(this);
        return false;
    }
    
    // 1.2 Get the status of the USB device (optional, for diag.)
    USBStatus status;
    err = pUsbDev->GetDeviceStatus(&status);
    if (err)
    {
        IOLog("%s(%p)::start - unable to get device status\n", getName(), this);
        pUsbDev->close(this);
        return false;
    }
    DEBUG_LOG("%s(%p)::start: device status %d\n", getName(), this, (int)status);

// rehabman:
// IOATH3KNULL can be used to create an IOath3kfrmwr.kext that effectively
// disables the device, so a 3rd party device can be used instead.
// To make this really work, there is probably additional device IDs that must be
// entered in the Info.plist
//
// Credit to mac4mat for this solution too...
    
#ifndef IOATH3KNULL
    // 2.0 Find the interface for bulk endpoint transfers
    IOUSBFindInterfaceRequest request;
    request.bInterfaceClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
    request.bAlternateSetting = kIOUSBFindInterfaceDontCare;
    
    IOUSBInterface * intf = pUsbDev->FindNextInterface(NULL, &request);
    if (!intf) {
        IOLog("%s(%p)::start - unable to find interface\n", getName(), this);
        pUsbDev->close(this);
        return false;
    }

    // 2.1 Open the interface
    if (!intf->open(this))
    {
        IOLog("%s(%p)::start - unable to open interface\n", getName(), this);
        pUsbDev->close(this);
        return false;
    }

    // 2.2 Get info on endpoints (optional, for diag.)
    DEBUG_LOG("%s(%p)::start: interface has %d endpoints\n", getName(), this, intf->GetNumEndpoints());
    
    OSArray* check = OSDynamicCast(OSArray, getProperty("CheckEndpoints"));
    if (check) {
        int count = check->getCount();
        for (int i = 0; i < count; i++) {
            OSDictionary* ep = OSDynamicCast(OSDictionary, check->getObject(i));
            if (!ep)
                continue;
            OSNumber* nEndpoint = OSDynamicCast(OSNumber, ep->getObject("EndpointNumber"));
            // TransferType: kUsbIn=1, kUsbOut=0
            OSNumber* nTransType = OSDynamicCast(OSNumber, ep->getObject("TransferType"));
            if (!nEndpoint || !nTransType)
                continue;
            UInt8 transferType = 0;
            UInt16 maxPacketSize = 0;
            UInt8 interval = 0;
            err = intf->GetEndpointProperties(0, nEndpoint->unsigned8BitValue(), nTransType->unsigned8BitValue(), &transferType, &maxPacketSize, &interval);
            if (err) {
                IOLog("%s(%p)::start - failed to get endpoint %d properties\n", getName(), this, i);
                intf->close(this);
                pUsbDev->close(this);
                return false;
            }
            DEBUG_LOG("%s(%p)::start: EP%d %d %d %d\n", getName(), this, nEndpoint->unsigned8BitValue(), transferType, maxPacketSize, interval);
        }
    }
    
    OSBoolean* ath3012 = OSDynamicCast(OSBoolean, getProperty("bAth3012"));
    if (ath3012->isTrue())
    {
        bool ret = false;
        
        do
        {
            OSNumber * bcdDevice = OSDynamicCast(OSNumber, getProperty("bcdDevice"));
            if ( bcdDevice->unsigned16BitValue() > 0x0001 )
                break;
            
            ret = load_patch( intf );
            if ( !ret )
            {
                IOLog("%s(%p)::start - loading patch failed\n", getName(), this);
                break;
            }
            
            ret = load_syscfg( intf );
            if ( !ret )
            {
                IOLog("%s(%p)::start - loading sysconfig failed\n", getName(), this);
                break;
            }
            
            ret = set_normal_mode( intf );
            if ( !ret )
            {
                IOLog("%s(%p)::start - set normal mode failed\n", getName(), this);
                break;
            }
            
            switch_pid( intf );
            
            ret = true;
        } while (false);
        
        if ( !ret )
        {
            intf->close(this);
            pUsbDev->close(this);
            return false;
        }
    }
    else
    {
        if (!load_firmware(intf, (const unsigned char *) firmware_buf, sizeof(firmware_buf)))
        {
            intf->close(this);
            pUsbDev->close(this);
            return false;
        }
    }
    
    /*  // TODO: Test the alternative way to do it:
     IOMemoryDescriptor * membuf = IOMemoryDescriptor::withAddress(&firmware_buf[20], 246804-20, kIODirectionNone); // sizeof(firmware_buf)
     if (!membuf) {
     IOLog("%s(%p)::start - failed to map memory descriptor\n", getName(), this);
     intf->close(this);
     pUsbDev->close(this);
     return false; 
     }
     err = membuf->prepare();
     if (err) {
     IOLog("%s(%p)::start - failed to prepare memory descriptor\n", getName(), this);
     intf->close(this);
     pUsbDev->close(this);
     return false; 
     }
     
     //err = pipe->Write(membuf);
     err = pipe->Write(membuf, 10000, 10000, 246804-20, NULL);
     if (err) {
     IOLog("%s(%p)::start - failed to write firmware to bulk pipe\n", getName(), this);
     intf->close(this);
     pUsbDev->close(this);
     return false; 
     }
     IOLog("%s(%p)::start: firmware was sent to bulk pipe\n", getName(), this);
     */
    
    // 4.0 Get device status (it fails, but somehow is important for operational device)
    err = pUsbDev->GetDeviceStatus(&status);
    if (err)
    {
        // this is the normal case...
        DEBUG_LOG("%s(%p)::start - unable to get device status\n", getName(), this);
    }
    else
    {
        // this is more of an error case... after firmware load
        // device status shouldn't work, as the devices has changed IDs
        IOLog("%s(%p)::start: device status %d\n", getName(), this, (int)status);
    }

    // Close the interface
    intf->close(this);

    // Close the USB device
    pUsbDev->close(this);
    return false;  // return false to allow a different driver to load
#else   // !IOATH3KNULL
    // Do not load the firmware, leave the controller non-operational
    
    // Do not close the USB device
    //pUsbDev->close(this);
    return true;  // return true to retain exclusive access to USB device
#endif  // !IOATH3KNULL
}

#ifdef DEBUG

void local_IOath3kfrmwr::stop(IOService *provider)
{
    DEBUG_LOG("%s(%p)::stop\n", getName(), this);
    super::stop(provider);
}

bool local_IOath3kfrmwr::handleOpen(IOService *forClient, IOOptionBits options, void *arg )
{
    DEBUG_LOG("%s(%p)::handleOpen\n", getName(), this);
    return super::handleOpen(forClient, options, arg);
}

void local_IOath3kfrmwr::handleClose(IOService *forClient, IOOptionBits options )
{
    DEBUG_LOG("%s(%p)::handleClose\n", getName(), this);
    super::handleClose(forClient, options);
}

IOReturn local_IOath3kfrmwr::message(UInt32 type, IOService *provider, void *argument)
{
    DEBUG_LOG("%s(%p)::message\n", getName(), this);
    switch ( type )
    {
        case kIOMessageServiceIsTerminated:
            if (pUsbDev->isOpen(this))
            {
                IOLog("%s(%p)::message - service is terminated - closing device\n", getName(), this);
//                pUsbDev->close(this);
            }
            break;
            
        case kIOMessageServiceIsSuspended:
        case kIOMessageServiceIsResumed:
        case kIOMessageServiceIsRequestingClose:
        case kIOMessageServiceWasClosed: 
        case kIOMessageServiceBusyStateChange:
        default:
            break;
    }
    
    return super::message(type, provider, argument);
}

bool local_IOath3kfrmwr::terminate(IOOptionBits options)
{
    DEBUG_LOG("%s(%p)::terminate\n", getName(), this);
    return super::terminate(options);
}

bool local_IOath3kfrmwr::finalize(IOOptionBits options)
{
    DEBUG_LOG("%s(%p)::finalize\n", getName(), this);
    return super::finalize(options);
}

#endif