#!/bin/bash
# Check characteristic flags for 1911

DEVICE_PATH="/org/bluez/hci0/dev_34_13_43_46_CA_84"

echo "Looking for 1911 characteristic..."

for svc in $(seq 0 20); do
    svc_hex=$(printf "%04x" $svc)
    svc_path="${DEVICE_PATH}/service${svc_hex}"

    for chr in $(seq 0 10); do
        chr_hex=$(printf "%04x" $chr)
        chr_path="${svc_path}/char${chr_hex}"

        result=$(gdbus call --system --dest org.bluez --object-path "$chr_path" \
            --method org.freedesktop.DBus.Properties.Get \
            org.bluez.GattCharacteristic1 UUID 2>/dev/null)

        if echo "$result" | grep -qi "1911"; then
            echo "Found 1911 at: $chr_path"
            echo ""

            echo "UUID:"
            echo "$result"
            echo ""

            echo "Flags:"
            gdbus call --system --dest org.bluez --object-path "$chr_path" \
                --method org.freedesktop.DBus.Properties.Get \
                org.bluez.GattCharacteristic1 Flags 2>&1
            echo ""

            echo "NotifyAcquired:"
            gdbus call --system --dest org.bluez --object-path "$chr_path" \
                --method org.freedesktop.DBus.Properties.Get \
                org.bluez.GattCharacteristic1 NotifyAcquired 2>&1
            echo ""

            echo "Notifying:"
            gdbus call --system --dest org.bluez --object-path "$chr_path" \
                --method org.freedesktop.DBus.Properties.Get \
                org.bluez.GattCharacteristic1 Notifying 2>&1

            exit 0
        fi
    done
done

echo "1911 not found - is device connected?"
