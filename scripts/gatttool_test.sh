#!/bin/bash
# Test Cync device using gatttool with expect

MAC="34:13:43:46:CA:84"
HANDLE_CCCD="0x0013"    # CCCD for 1911 (handle 17/0x11, +2 = 19/0x13)
HANDLE_1912="0x0014"    # Write handle for 1912 (handle 20)
HANDLE_1911="0x0011"    # Notify handle for 1911 (handle 17)

echo "============================================"
echo "GATTTOOL CYNC TEST"
echo "============================================"
echo ""

# Use expect to automate gatttool
expect << 'EOF'
set timeout 30

spawn gatttool -I -b 34:13:43:46:CA:84

expect ">"
send "connect\r"
expect "Connection successful"
puts "\n\[Connected\]"

# Wait a moment
sleep 1

# Enable notifications by writing 0x0100 to CCCD
puts "\n\[Enabling notifications...\]"
send "char-write-req 0x0013 0100\r"
expect {
    "Characteristic value was written successfully" {
        puts "\[CCCD write OK\]"
    }
    "failed" {
        puts "\[CCCD write FAILED\]"
    }
    timeout {
        puts "\[CCCD write timeout\]"
    }
}

sleep 0.5

# Send handshake commands
puts "\n\[Sending handshake...\]"

set cmds {
    "000501000000000000000000"
    "00000100000000000000040000"
    "3100"
    "3101"
    "3102"
    "3103"
    "3104"
    "00000100000000000000160000"
    "00000100000000000000010002"
    "320119000000"
}

foreach cmd $cmds {
    puts "  -> $cmd"
    send "char-write-cmd 0x0014 $cmd\r"
    expect {
        "Notification handle" {
            puts "  <- NOTIFY: \[response\]"
        }
        ">" {
            # No response, continue
        }
        timeout {
            puts "  (timeout)"
        }
    }
    sleep 0.3
}

puts "\n\[Sending ON command...\]"
send "char-write-cmd 0x0014 b0c00101\r"
expect ">"
sleep 3

puts "\n\[Sending OFF command...\]"
send "char-write-cmd 0x0014 b0c00100\r"
expect ">"
sleep 3

puts "\n\[Done - disconnecting...\]"
send "disconnect\r"
expect ">"
send "quit\r"
EOF

echo ""
echo "Test complete. Did the light change?"
