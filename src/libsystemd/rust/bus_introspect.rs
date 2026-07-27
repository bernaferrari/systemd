// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: conservative Rust shadow of src/libsystemd/sd-bus/bus-introspect.c

/// XML snippets for standard D-Bus introspection interfaces.
pub const BUS_INTROSPECT_INTERFACE_PEER: &[u8] = b" \
 <interface name=\"org.freedesktop.DBus.Peer\">\n \
  <method name=\"Ping\"/>\n \
  <method name=\"GetMachineId\">\n \
   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n \
  </method>\n \
 </interface>\n";

pub const BUS_INTROSPECT_INTERFACE_INTROSPECTABLE: &[u8] = b" \
 <interface name=\"org.freedesktop.DBus.Introspectable\">\n \
  <method name=\"Introspect\">\n \
   <arg name=\"xml_data\" type=\"s\" direction=\"out\"/>\n \
  </method>\n \
 </interface>\n";

pub const BUS_INTROSPECT_INTERFACE_PROPERTIES: &[u8] = b" \
 <interface name=\"org.freedesktop.DBus.Properties\">\n \
  <method name=\"Get\">\n \
   <arg name=\"interface_name\" direction=\"in\" type=\"s\"/>\n \
   <arg name=\"property_name\" direction=\"in\" type=\"s\"/>\n \
   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n \
  </method>\n \
  <method name=\"GetAll\">\n \
   <arg name=\"interface_name\" direction=\"in\" type=\"s\"/>\n \
   <arg name=\"props\" direction=\"out\" type=\"a{sv}\"/>\n \
  </method>\n \
  <method name=\"Set\">\n \
   <arg name=\"interface_name\" direction=\"in\" type=\"s\"/>\n \
   <arg name=\"property_name\" direction=\"in\" type=\"s\"/>\n \
   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n \
  </method>\n \
  <signal name=\"PropertiesChanged\">\n \
   <arg type=\"s\" name=\"interface_name\"/>\n \
   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n \
   <arg type=\"as\" name=\"invalidated_properties\"/>\n \
  </signal>\n \
 </interface>\n";

pub const BUS_INTROSPECT_INTERFACE_OBJECT_MANAGER: &[u8] = b" \
 <interface name=\"org.freedesktop.DBus.ObjectManager\">\n \
  <method name=\"GetManagedObjects\">\n \
   <arg type=\"a{oa{sa{sv}}}\" name=\"object_paths_interfaces_and_properties\" direction=\"out\"/>\n \
  </method>\n \
  <signal name=\"InterfacesAdded\">\n \
   <arg type=\"o\" name=\"object_path\"/>\n \
   <arg type=\"a{sa{sv}}\" name=\"interfaces_and_properties\"/>\n \
  </signal>\n \
  <signal name=\"InterfacesRemoved\">\n \
   <arg type=\"o\" name=\"object_path\"/>\n \
   <arg type=\"as\" name=\"interfaces\"/>\n \
  </signal>\n \
 </interface>\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_introspect_constants_contain_expected_tags() {
        assert!(std::str::from_utf8(BUS_INTROSPECT_INTERFACE_PEER)
            .unwrap()
            .contains("org.freedesktop.DBus.Peer"));
        assert!(std::str::from_utf8(BUS_INTROSPECT_INTERFACE_INTROSPECTABLE)
            .unwrap()
            .contains("Introspect"));
        assert!(std::str::from_utf8(BUS_INTROSPECT_INTERFACE_PROPERTIES)
            .unwrap()
            .contains("Properties"));
        assert!(std::str::from_utf8(BUS_INTROSPECT_INTERFACE_OBJECT_MANAGER)
            .unwrap()
            .contains("ObjectManager"));
    }
}
