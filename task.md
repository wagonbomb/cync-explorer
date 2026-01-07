# GE Cync Lighting Discovery & Control

## Tasks

- [x] Create BLE discovery and exploration tools
  - [x] BLE scanner to find devices
  - [x] GATT service/characteristic explorer
  - [x] Interactive controller for testing commands
- [/] Test discovery tools against the Cync light (MAC: 34134346ca85)
  - [x] BLE scan - found device as `34:13:43:46:CA:84` (-1 offset)
  - [/] Connection failed due to weak signal (-100 dBm)
- [x] Analyze discovered services and characteristics
  - Identified Telink Semiconductor (0x0211) chips
  - Found Service UUID `00001828` (Mesh/Provisioning)
- [/] Attempt to control the light (on/off, brightness, color)
  - [x] Basic On/Off via Web GUI (Telink UUID `...1911`)
- [ ] **Bypass Mesh Encryption** (Current Priority)
  - [x] Run Forensic Deep Scan (Confirmed Mesh Proxy 1828)
  - [ ] **Extract Keys via HCI Snoop** (Golden Path - Passive/Non-Destructive)
- [ ] Document findings and create reusable control library

