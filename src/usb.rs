//! USB port inventory: how many ports the computer has, what kind they are,
//! which are in use, and what is plugged into each.
//!
//! Windows reports *logical* ports per hub. A USB 3 socket appears twice
//! (once on the USB 2 side and once on the SuperSpeed side) and the two are
//! linked as "companions". We merge companions so every physical socket is
//! counted once.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct UsbDevice {
    pub name: String,
    pub vid: u16,
    pub pid: u16,
    /// 0 low, 1 full, 2 high, 3 super (Windows USB_DEVICE_SPEED).
    pub speed: u8,
    pub superspeed_plus: bool,
    /// bcdUSB from the device descriptor, e.g. 0x0320 for USB 3.2.
    pub bcd_usb: u16,
    pub is_hub: bool,
}

impl UsbDevice {
    pub fn identity(&self) -> String {
        format!("{:04X}:{:04X} {}", self.vid, self.pid, self.name)
    }
    pub fn speed_text(&self) -> &'static str {
        if self.superspeed_plus {
            return "SuperSpeed+ (10 Gbps or more, USB 3.1/3.2)";
        }
        match self.speed {
            3 => "SuperSpeed (5 Gbps, USB 3.x)",
            2 => "High speed (480 Mbps, USB 2.0)",
            1 => "Full speed (12 Mbps, USB 1.1)",
            0 => "Low speed (1.5 Mbps, USB 1.0)",
            _ => "unknown speed",
        }
    }
    /// The device itself supports USB 3 (bcdUSB 3.0 or higher).
    pub fn usb3_capable(&self) -> bool {
        self.bcd_usb >= 0x0300
    }
}

/// One port as Windows reports it on one hub.
#[derive(Clone, Debug, Default)]
pub struct LogicalPort {
    /// Normalised hub symbolic link (lower case, no \\?\ prefix).
    pub hub_key: String,
    pub hub_name: String,
    pub hub_is_root: bool,
    pub port: u32,
    pub user_connectable: bool,
    pub type_c: bool,
    pub usb110: bool,
    pub usb200: bool,
    pub usb300: bool,
    pub companion: Option<(String, u32)>,
    pub device: Option<UsbDevice>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Location {
    /// A socket on the computer itself.
    BuiltIn,
    /// Wired inside the case (webcam, Bluetooth, fingerprint reader...).
    Internal,
    /// A socket on a hub, dock or monitor plugged into the computer.
    ExternalHub,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhysicalPort {
    /// Stable id: the first logical port of the group.
    pub id: String,
    pub label: String,
    pub location: Location,
    pub hub_name: String,
    pub usb3: bool,
    pub usb2: bool,
    pub type_c: bool,
    pub device: Option<UsbDevice>,
    pub logical: Vec<String>,
}

impl PhysicalPort {
    pub fn in_use(&self) -> bool {
        self.device.is_some()
    }
    pub fn kind(&self) -> &'static str {
        if self.usb3 {
            "USB 3.x"
        } else if self.usb2 {
            "USB 2.0"
        } else {
            "USB 1.1"
        }
    }
    pub fn connector(&self) -> &'static str {
        if self.location == Location::Internal {
            "internal"
        } else if self.type_c {
            "USB-C"
        } else {
            "Type-A or other"
        }
    }
    /// A USB 3 device running at USB 2 speed in a USB 3 socket.
    pub fn slow_link_warning(&self) -> Option<String> {
        let d = self.device.as_ref()?;
        if self.usb3 && d.usb3_capable() && d.speed < 3 && !d.superspeed_plus {
            Some("USB 3 device is running at USB 2 speed. Re-plug it firmly or try another cable.".into())
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct UsbReport {
    pub ports: Vec<PhysicalPort>,
    pub hubs_seen: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct UsbSummary {
    pub built_in: usize,
    pub built_in_in_use: usize,
    pub built_in_free: usize,
    pub built_in_usb3: usize,
    pub built_in_usb2_only: usize,
    pub built_in_type_c: usize,
    pub hub_ports: usize,
    pub hub_ports_in_use: usize,
    pub internal_devices: usize,
}

impl UsbReport {
    pub fn summary(&self) -> UsbSummary {
        let mut s = UsbSummary::default();
        for p in &self.ports {
            match p.location {
                Location::BuiltIn => {
                    s.built_in += 1;
                    if p.in_use() {
                        s.built_in_in_use += 1;
                    }
                    if p.usb3 {
                        s.built_in_usb3 += 1;
                    } else {
                        s.built_in_usb2_only += 1;
                    }
                    if p.type_c {
                        s.built_in_type_c += 1;
                    }
                }
                Location::ExternalHub => {
                    s.hub_ports += 1;
                    if p.in_use() {
                        s.hub_ports_in_use += 1;
                    }
                }
                Location::Internal => {
                    if p.in_use() {
                        s.internal_devices += 1;
                    }
                }
            }
        }
        s.built_in_free = s.built_in - s.built_in_in_use;
        s
    }
}

fn key(hub: &str, port: u32) -> String {
    format!("{hub}#{port}")
}

/// Normalise a hub path so "\\?\USB#ROOT_HUB30#..." and "USB#ROOT_HUB30#..."
/// compare equal.
pub fn normalise_hub(p: &str) -> String {
    p.trim_start_matches(r"\\?\").trim_start_matches(r"\??\").to_ascii_lowercase()
}

/// Merge companion logical ports into physical sockets.
pub fn group_ports(logical: &[LogicalPort]) -> Vec<PhysicalPort> {
    let index: HashMap<String, usize> =
        logical.iter().enumerate().map(|(i, l)| (key(&l.hub_key, l.port), i)).collect();

    // Union-find.
    let mut parent: Vec<usize> = (0..logical.len()).collect();
    fn find(p: &mut Vec<usize>, i: usize) -> usize {
        let mut r = i;
        while p[r] != r {
            r = p[r];
        }
        let mut c = i;
        while p[c] != r {
            let n = p[c];
            p[c] = r;
            c = n;
        }
        r
    }
    for (i, l) in logical.iter().enumerate() {
        if let Some((hub, port)) = &l.companion {
            if let Some(&j) = index.get(&key(&normalise_hub(hub), *port)) {
                let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                if a != b {
                    parent[a] = b;
                }
            }
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..logical.len() {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut out: Vec<PhysicalPort> = groups
        .into_values()
        .map(|members| {
            let ls: Vec<&LogicalPort> = members.iter().map(|&i| &logical[i]).collect();
            let any_root = ls.iter().any(|l| l.hub_is_root);
            let connectable = ls.iter().any(|l| l.user_connectable);
            let location = if !any_root {
                Location::ExternalHub
            } else if connectable {
                Location::BuiltIn
            } else {
                Location::Internal
            };
            // Prefer the device on the fastest link.
            let device = ls
                .iter()
                .filter_map(|l| l.device.clone())
                .max_by_key(|d| (d.superspeed_plus, d.speed));
            let mut ids: Vec<String> = ls.iter().map(|l| key(&l.hub_key, l.port)).collect();
            ids.sort();
            let hub_name = ls
                .iter()
                .find(|l| l.usb200 || l.usb110)
                .or(ls.first())
                .map(|l| l.hub_name.clone())
                .unwrap_or_default();
            PhysicalPort {
                id: ids[0].clone(),
                label: String::new(),
                location,
                hub_name,
                usb3: ls.iter().any(|l| l.usb300),
                usb2: ls.iter().any(|l| l.usb200 || l.usb110),
                type_c: ls.iter().any(|l| l.type_c),
                device,
                logical: ids,
            }
        })
        .collect();

    out.sort_by(|a, b| (a.location, &a.id).cmp(&(b.location, &b.id)));
    let mut counters: HashMap<Location, usize> = HashMap::new();
    for p in &mut out {
        let n = counters.entry(p.location).or_insert(0);
        *n += 1;
        p.label = match p.location {
            Location::BuiltIn => format!("Port {n}"),
            Location::Internal => format!("Internal {n}"),
            Location::ExternalHub => format!("Hub port {n}"),
        };
    }
    out
}

#[derive(Clone, Debug, PartialEq)]
pub enum UsbChange {
    Connected { port: String, kind: String, device: UsbDevice, location: Location },
    Disconnected { port: String, device: UsbDevice, location: Location },
}

impl UsbChange {
    pub fn message(&self) -> String {
        match self {
            UsbChange::Connected { port, kind, device, location } => format!(
                "USB device connected: {} (ID {:04X}:{:04X}) on {} {} [{}], {}",
                device.name,
                device.vid,
                device.pid,
                where_text(*location),
                port,
                kind,
                device.speed_text()
            ),
            UsbChange::Disconnected { port, device, location } => format!(
                "USB device removed: {} (ID {:04X}:{:04X}) from {} {}",
                device.name, device.vid, device.pid, where_text(*location), port
            ),
        }
    }
}

fn where_text(l: Location) -> &'static str {
    match l {
        Location::BuiltIn => "built-in",
        Location::Internal => "internal",
        Location::ExternalHub => "hub",
    }
}

/// What changed between two reports.
pub fn diff(old: &UsbReport, new: &UsbReport) -> Vec<UsbChange> {
    let before: HashMap<&str, &PhysicalPort> = old.ports.iter().map(|p| (p.id.as_str(), p)).collect();
    let after: HashMap<&str, &PhysicalPort> = new.ports.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut out = Vec::new();
    for p in &new.ports {
        let prev = before.get(p.id.as_str()).and_then(|o| o.device.as_ref());
        match (prev, &p.device) {
            (None, Some(d)) => out.push(UsbChange::Connected {
                port: p.label.clone(),
                kind: format!("{} {}", p.kind(), p.connector()),
                device: d.clone(),
                location: p.location,
            }),
            (Some(a), Some(b)) if a.identity() != b.identity() => {
                out.push(UsbChange::Disconnected { port: p.label.clone(), device: a.clone(), location: p.location });
                out.push(UsbChange::Connected {
                    port: p.label.clone(),
                    kind: format!("{} {}", p.kind(), p.connector()),
                    device: b.clone(),
                    location: p.location,
                });
            }
            (Some(a), None) => {
                out.push(UsbChange::Disconnected { port: p.label.clone(), device: a.clone(), location: p.location })
            }
            _ => {}
        }
    }
    // Ports that vanished entirely (for example a hub was unplugged).
    for p in &old.ports {
        if !after.contains_key(p.id.as_str()) {
            if let Some(d) = &p.device {
                out.push(UsbChange::Disconnected { port: p.label.clone(), device: d.clone(), location: p.location });
            }
        }
    }
    out
}

/// Read the live USB layout from Windows.
pub fn scan() -> UsbReport {
    #[cfg(windows)]
    {
        win::scan()
    }
    #[cfg(not(windows))]
    {
        if std::env::var_os("BIMBO_GUARD_DEMO").is_some() {
            return demo();
        }
        UsbReport { errors: vec!["USB port details are only available on Windows".into()], ..Default::default() }
    }
}

/// Sample data so the interface can be previewed off Windows.
#[cfg(not(windows))]
fn demo() -> UsbReport {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let stick = (secs / 20) % 2 == 0;
    let mk = |hub: &str, root: bool, port: u32, conn: bool, c: bool, u2: bool, u3: bool, comp: Option<(&str, u32)>, dev: Option<UsbDevice>| LogicalPort {
        hub_key: hub.into(),
        hub_name: if root { "USB root hub".into() } else { "Generic USB hub".into() },
        hub_is_root: root,
        port,
        user_connectable: conn,
        type_c: c,
        usb110: false,
        usb200: u2,
        usb300: u3,
        companion: comp.map(|(h, p)| (h.to_string(), p)),
        device: dev,
    };
    let dev = |name: &str, vid, pid, speed, bcd| UsbDevice { name: name.into(), vid, pid, speed, superspeed_plus: false, bcd_usb: bcd, is_hub: false };
    let l = vec![
        mk("root", true, 1, true, false, true, false, Some(("root", 5)), Some(dev("USB Optical Mouse", 0x046D, 0xC077, 1, 0x0200))),
        mk("root", true, 2, true, false, true, false, Some(("root", 6)), None),
        mk("root", true, 3, true, true, true, false, Some(("root", 7)), None),
        mk("root", true, 4, false, false, true, false, None, Some(dev("Integrated Webcam", 0x0BDA, 0x58C2, 2, 0x0200))),
        mk("root", true, 5, true, false, false, true, Some(("root", 1)), None),
        mk("root", true, 6, true, false, false, true, Some(("root", 2)), if stick { Some(dev("SanDisk Ultra USB 3.0", 0x0781, 0x5591, 3, 0x0320)) } else { None }),
        mk("root", true, 7, true, true, false, true, Some(("root", 3)), None),
        mk("root", true, 8, true, false, true, false, None, None),
    ];
    UsbReport { ports: group_ports(&l), hubs_seen: 1, errors: vec![] }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
    use windows_sys::Win32::Devices::Usb::*;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_WRITE, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    unsafe fn ioctl<T>(h: HANDLE, code: u32, buf: *mut T, len: usize) -> bool {
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(h, code, buf as *const c_void, len as u32, buf as *mut c_void, len as u32, &mut ret, std::ptr::null_mut()) != 0
        }
    }

    struct Hub {
        path: String,
        instance: String,
        name: String,
    }

    /// Every USB hub (root hubs in the controllers, plus external hubs).
    fn hubs() -> Vec<Hub> {
        let mut out = Vec::new();
        unsafe {
            let set = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_HUB, std::ptr::null(), std::ptr::null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            if set == -1 {
                return out;
            }
            let mut i = 0;
            loop {
                let mut ifd: SP_DEVICE_INTERFACE_DATA = zeroed();
                ifd.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
                if SetupDiEnumDeviceInterfaces(set, std::ptr::null(), &GUID_DEVINTERFACE_USB_HUB, i, &mut ifd) == 0 {
                    break;
                }
                i += 1;
                let mut need = 0u32;
                SetupDiGetDeviceInterfaceDetailW(set, &ifd, std::ptr::null_mut(), 0, &mut need, std::ptr::null_mut());
                if need == 0 {
                    continue;
                }
                let mut buf = vec![0u64; (need as usize).div_ceil(8) + 1];
                let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
                (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
                let mut dev: SP_DEVINFO_DATA = zeroed();
                dev.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
                if SetupDiGetDeviceInterfaceDetailW(set, &ifd, detail, need, std::ptr::null_mut(), &mut dev) == 0 {
                    continue;
                }
                let path_ptr = std::ptr::addr_of!((*detail).DevicePath) as *const u16;
                let path_len = (need as usize - 4) / 2;
                let path = from_wide(std::slice::from_raw_parts(path_ptr, path_len));
                let mut inst = [0u16; 512];
                SetupDiGetDeviceInstanceIdW(set, &dev, inst.as_mut_ptr(), inst.len() as u32, std::ptr::null_mut());
                let name = reg_prop(set, &dev, SPDRP_FRIENDLYNAME).or_else(|| reg_prop(set, &dev, SPDRP_DEVICEDESC)).unwrap_or_default();
                out.push(Hub { path, instance: from_wide(&inst), name });
            }
            SetupDiDestroyDeviceInfoList(set);
        }
        out
    }

    unsafe fn reg_prop(set: HDEVINFO, dev: &SP_DEVINFO_DATA, prop: u32) -> Option<String> {
        let mut buf = [0u16; 512];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(set, dev, prop, std::ptr::null_mut(), buf.as_mut_ptr() as *mut u8, (buf.len() * 2) as u32, std::ptr::null_mut())
        };
        if ok == 0 {
            return None;
        }
        let s = from_wide(&buf);
        (!s.is_empty()).then_some(s)
    }

    /// Driver key -> friendly device name, for naming plugged-in devices.
    fn device_names() -> HashMap<String, String> {
        let mut map = HashMap::new();
        unsafe {
            let set = SetupDiGetClassDevsW(std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), DIGCF_ALLCLASSES | DIGCF_PRESENT);
            if set == -1 {
                return map;
            }
            let mut i = 0;
            loop {
                let mut dev: SP_DEVINFO_DATA = zeroed();
                dev.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
                if SetupDiEnumDeviceInfo(set, i, &mut dev) == 0 {
                    break;
                }
                i += 1;
                if let Some(drv) = reg_prop(set, &dev, SPDRP_DRIVER) {
                    let name = reg_prop(set, &dev, SPDRP_FRIENDLYNAME).or_else(|| reg_prop(set, &dev, SPDRP_DEVICEDESC)).unwrap_or_default();
                    map.insert(drv.to_ascii_lowercase(), name);
                }
            }
            SetupDiDestroyDeviceInfoList(set);
        }
        map
    }

    pub fn scan() -> UsbReport {
        let names = device_names();
        let mut logical = Vec::new();
        let mut errors = Vec::new();
        let hubs = hubs();
        for hub in &hubs {
            let w = wide(&hub.path);
            let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_WRITE, FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
            if h == INVALID_HANDLE_VALUE || h.is_null() {
                errors.push(format!("Could not open hub {}", hub.name));
                continue;
            }
            let hub_key = normalise_hub(&hub.path);
            let is_root = hub.instance.to_ascii_uppercase().starts_with(r"USB\ROOT_HUB");
            unsafe {
                let mut ni: USB_NODE_INFORMATION = zeroed();
                if !ioctl(h, IOCTL_USB_GET_NODE_INFORMATION, &mut ni, size_of::<USB_NODE_INFORMATION>()) {
                    errors.push(format!("Could not read hub {}", hub.name));
                    CloseHandle(h);
                    continue;
                }
                let nports = ni.u.HubInformation.HubDescriptor.bNumberOfPorts as u32;
                for port in 1..=nports {
                    let mut lp = LogicalPort {
                        hub_key: hub_key.clone(),
                        hub_name: hub.name.clone(),
                        hub_is_root: is_root,
                        port,
                        user_connectable: true,
                        usb200: true,
                        ..Default::default()
                    };

                    // Connector properties: user-visible, USB-C, companion.
                    let mut cp: USB_PORT_CONNECTOR_PROPERTIES = zeroed();
                    cp.ConnectionIndex = port;
                    if ioctl(h, IOCTL_USB_GET_PORT_CONNECTOR_PROPERTIES, &mut cp, size_of::<USB_PORT_CONNECTOR_PROPERTIES>()) {
                        let need = (cp.ActualLength as usize).max(size_of::<USB_PORT_CONNECTOR_PROPERTIES>());
                        let mut buf = vec![0u64; need.div_ceil(8) + 1];
                        let full = buf.as_mut_ptr() as *mut USB_PORT_CONNECTOR_PROPERTIES;
                        (*full).ConnectionIndex = port;
                        if ioctl(h, IOCTL_USB_GET_PORT_CONNECTOR_PROPERTIES, full, need) {
                            let props = (*full).UsbPortProperties.ul;
                            lp.user_connectable = props & 0x1 != 0;
                            lp.type_c = props & 0x8 != 0;
                            let comp_port = (*full).CompanionPortNumber as u32;
                            if comp_port != 0 {
                                let name_ptr = std::ptr::addr_of!((*full).CompanionHubSymbolicLinkName) as *const u16;
                                let max = (need.saturating_sub(std::mem::offset_of!(USB_PORT_CONNECTOR_PROPERTIES, CompanionHubSymbolicLinkName))) / 2;
                                let comp_hub = from_wide(std::slice::from_raw_parts(name_ptr, max));
                                let comp_hub = if comp_hub.is_empty() { hub_key.clone() } else { comp_hub };
                                lp.companion = Some((comp_hub, comp_port));
                            }
                        }
                    }

                    // Which USB versions this port supports.
                    let mut v2: USB_NODE_CONNECTION_INFORMATION_EX_V2 = zeroed();
                    v2.ConnectionIndex = port;
                    v2.Length = size_of::<USB_NODE_CONNECTION_INFORMATION_EX_V2>() as u32;
                    v2.SupportedUsbProtocols.ul = 0b111;
                    let mut ss_plus = false;
                    let mut ss_now = false;
                    if ioctl(h, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX_V2, &mut v2, size_of::<USB_NODE_CONNECTION_INFORMATION_EX_V2>()) {
                        let p = v2.SupportedUsbProtocols.ul;
                        lp.usb110 = p & 0x1 != 0;
                        lp.usb200 = p & 0x2 != 0;
                        lp.usb300 = p & 0x4 != 0;
                        let f = v2.Flags.ul;
                        ss_now = f & 0x1 != 0;
                        ss_plus = f & 0x4 != 0;
                    }

                    // What is connected, if anything.
                    let size = size_of::<USB_NODE_CONNECTION_INFORMATION_EX>() + 32 * size_of::<USB_PIPE_INFO>();
                    let mut buf = vec![0u64; size.div_ceil(8)];
                    let ci = buf.as_mut_ptr() as *mut USB_NODE_CONNECTION_INFORMATION_EX;
                    (*ci).ConnectionIndex = port;
                    if ioctl(h, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX, ci, size) && (*ci).ConnectionStatus == DeviceConnected {
                        let desc = (*ci).DeviceDescriptor;
                        let mut speed = (*ci).Speed;
                        if ss_now && speed < 3 {
                            speed = 3;
                        }
                        let mut d = UsbDevice {
                            name: String::new(),
                            vid: desc.idVendor,
                            pid: desc.idProduct,
                            speed,
                            superspeed_plus: ss_plus,
                            bcd_usb: desc.bcdUSB,
                            is_hub: (*ci).DeviceIsHub,
                        };
                        d.name = driver_key(h, port).and_then(|k| names.get(&k.to_ascii_lowercase()).cloned()).unwrap_or_else(|| {
                            if d.is_hub { "USB hub".into() } else { "USB device".into() }
                        });
                        lp.device = Some(d);
                    }
                    logical.push(lp);
                }
                CloseHandle(h);
            }
        }
        if hubs.is_empty() {
            errors.push("No USB hubs found".into());
        }
        UsbReport { ports: group_ports(&logical), hubs_seen: hubs.len(), errors }
    }

    unsafe fn driver_key(h: HANDLE, port: u32) -> Option<String> {
        unsafe {
            let mut probe: USB_NODE_CONNECTION_DRIVERKEY_NAME = zeroed();
            probe.ConnectionIndex = port;
            if !ioctl(h, IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME, &mut probe, size_of::<USB_NODE_CONNECTION_DRIVERKEY_NAME>()) {
                return None;
            }
            let need = (probe.ActualLength as usize).max(size_of::<USB_NODE_CONNECTION_DRIVERKEY_NAME>());
            let mut buf = vec![0u64; need.div_ceil(8) + 1];
            let full = buf.as_mut_ptr() as *mut USB_NODE_CONNECTION_DRIVERKEY_NAME;
            (*full).ConnectionIndex = port;
            if !ioctl(h, IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME, full, need) {
                return None;
            }
            let ptr = std::ptr::addr_of!((*full).DriverKeyName) as *const u16;
            let max = need.saturating_sub(8) / 2;
            let s = from_wide(std::slice::from_raw_parts(ptr, max));
            (!s.is_empty()).then_some(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lp(hub: &str, root: bool, port: u32, conn: bool, u2: bool, u3: bool, comp: Option<(&str, u32)>, dev: Option<UsbDevice>) -> LogicalPort {
        LogicalPort {
            hub_key: hub.into(),
            hub_name: hub.into(),
            hub_is_root: root,
            port,
            user_connectable: conn,
            usb200: u2,
            usb300: u3,
            companion: comp.map(|(h, p)| (h.into(), p)),
            device: dev,
            ..Default::default()
        }
    }
    fn dev(speed: u8, bcd: u16) -> UsbDevice {
        UsbDevice { name: "Stick".into(), vid: 1, pid: 2, speed, bcd_usb: bcd, ..Default::default() }
    }

    #[test]
    fn companions_merge_into_one_socket() {
        // Two USB 3 sockets (each = USB2 lane + SS lane), one USB 2-only socket,
        // one internal webcam port.
        let l = vec![
            lp("r", true, 1, true, true, false, Some((r"\\?\R", 5)), None),
            lp("r", true, 2, true, true, false, Some(("r", 6)), None),
            lp("r", true, 3, true, true, false, None, Some(dev(2, 0x200))),
            lp("r", true, 4, false, true, false, None, Some(dev(2, 0x200))),
            lp("r", true, 5, true, false, true, Some(("r", 1)), Some(dev(3, 0x320))),
            lp("r", true, 6, true, false, true, Some(("r", 2)), None),
        ];
        let ports = group_ports(&l);
        let r = UsbReport { ports, hubs_seen: 1, errors: vec![] };
        let s = r.summary();
        assert_eq!(s.built_in, 3);
        assert_eq!(s.built_in_usb3, 2);
        assert_eq!(s.built_in_usb2_only, 1);
        assert_eq!(s.built_in_in_use, 2);
        assert_eq!(s.built_in_free, 1);
        assert_eq!(s.internal_devices, 1);
    }

    #[test]
    fn diff_reports_connect_and_remove() {
        let a = UsbReport { ports: group_ports(&[lp("r", true, 1, true, true, true, None, None)]), ..Default::default() };
        let b = UsbReport { ports: group_ports(&[lp("r", true, 1, true, true, true, None, Some(dev(3, 0x300)))]), ..Default::default() };
        let c = diff(&a, &b);
        assert!(matches!(c.as_slice(), [UsbChange::Connected { .. }]));
        assert!(c[0].message().contains("built-in Port 1"));
        let d = diff(&b, &a);
        assert!(matches!(d.as_slice(), [UsbChange::Disconnected { .. }]));
        assert!(diff(&b, &b).is_empty());
    }

    #[test]
    fn slow_link_warning() {
        let mut p = group_ports(&[lp("r", true, 1, true, true, true, None, Some(dev(2, 0x320)))]);
        assert!(p[0].slow_link_warning().is_some());
        p[0].device = Some(dev(3, 0x320));
        assert!(p[0].slow_link_warning().is_none());
    }
}
