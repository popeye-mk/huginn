//go:build linux

package collectors

import (
	"context"
	"net"
	"path/filepath"
	"strings"

	"netdiag/internal/schema"
)

// ----------------------------------- NIC power management (L1, §4.1 v2.3)

// powerCollector reads runtime power-management state for the primary NIC —
// the #1 cause of "the Wi-Fi drops when the laptop sits idle" — and whether
// the NIC hangs off USB (docks; selective-suspend victims).
type powerCollector struct{}

func (powerCollector) Name() string      { return "nic_power" }
func (powerCollector) Privilege() string { return schema.PrivUnprivileged }

func (powerCollector) Collect(_ context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	data := map[string]any{}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		base := filepath.Join("/sys/class/net", ifc.Name)
		ctl := sysRead(filepath.Join(base, "device", "power"), "control")
		if ctl == "" {
			continue // virtual iface or /sys not exposing PM — nothing to claim
		}
		data["nic_power_saving"] = ctl == "auto" // runtime PM allowed to suspend the NIC
		data["nic_power_iface"] = ifc.Name
		// Driver name/version (§4.1 "driver name/version/date").
		if drv, err := filepath.EvalSymlinks(filepath.Join(base, "device", "driver")); err == nil {
			name := filepath.Base(drv)
			data["nic_driver"] = name
			if v := sysRead(filepath.Join("/sys/module", name), "version"); v != "" {
				data["nic_driver_version"] = v
			}
		}
		if dev, err := filepath.EvalSymlinks(filepath.Join(base, "device")); err == nil {
			onUSB := strings.Contains(dev, "/usb")
			data["nic_on_usb"] = onUSB
			// USB selective-suspend detail: autosuspend enabled on the
			// USB parent is the dock-NIC drop-out recipe.
			if onUSB {
				usbDev := dev
				for i := 0; i < 4; i++ { // walk up to the USB device node
					if m, _ := filepath.Glob(filepath.Join(usbDev, "power", "autosuspend_delay_ms")); len(m) > 0 {
						break
					}
					usbDev = filepath.Dir(usbDev)
				}
				if ctlUSB := sysRead(filepath.Join(usbDev, "power"), "control"); ctlUSB != "" {
					data["usb_autosuspend"] = ctlUSB == "auto"
				}
			}
		}
		break // primary up NIC only in v1
	}
	return data, nil
}
