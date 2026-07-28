// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-usb_id.c
//
// USB identifier synthesis.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceId {
    pub vendor: u16,
    pub product: u16,
    pub revision: Option<u16>,
    pub interface_class: Option<u8>,
}

pub fn usb_id_properties(id: UsbDeviceId) -> BTreeMap<String, String> {
    let mut map = BTreeMap::from([
        ("ID_VENDOR_ID".into(), format!("{:04x}", id.vendor)),
        ("ID_MODEL_ID".into(), format!("{:04x}", id.product)),
    ]);
    if let Some(revision) = id.revision {
        map.insert("ID_REVISION".into(), format!("{:04x}", revision));
    }
    if let Some(class) = id.interface_class {
        map.insert("ID_USB_INTERFACES".into(), format!(":{:02x}:", class));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_identifiers_as_hex() {
        let props = usb_id_properties(UsbDeviceId {
            vendor: 0x1234,
            product: 0xabcd,
            revision: Some(0x0102),
            interface_class: Some(0x03),
        });
        assert_eq!(props["ID_VENDOR_ID"], "1234");
        assert_eq!(props["ID_USB_INTERFACES"], ":03:");
    }
    #[test]
    fn omits_optional_fields() {
        let props = usb_id_properties(UsbDeviceId {
            vendor: 1,
            product: 2,
            revision: None,
            interface_class: None,
        });
        assert!(!props.contains_key("ID_REVISION"));
    }
}
