# Tests for smb-server workload
pre_start_smb-server() {
    # Write a minimal smb.conf — required_files means it must exist before start
    local home
    home=$(getent passwd _wl-smb-server 2>/dev/null | cut -d: -f6) || return
    [ -d "$home" ] || return
    [ -d "$home/smb.conf" ] && rm -rf "$home/smb.conf"
    if [ ! -f "$home/smb.conf" ]; then
        cat > "$home/smb.conf" <<'EOF'
[global]
    workgroup = WORKGROUP
    server role = standalone server
    security = user
    map to guest = Bad User
    logging = systemd
    log level = 1
    smb ports = 445
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes

[testshare]
    path = /exports
    browseable = yes
    writable = yes
    guest ok = yes
    force user = _wl-smb-server
    create mask = 0664
    directory mask = 0775
EOF
        chown _wl-smb-server: "$home/smb.conf"
    fi
}

test_smb-server() {
    if ! systemctl is-active --quiet workload-smb-server.service; then
        fail "smb-server: service not active, skipping tests"
        return
    fi

    # Service file checks: host networking
    local svc
    svc=$(cat /run/systemd/system/workload-smb-server.service 2>/dev/null || echo "")
    if [ -n "$svc" ]; then
        if echo "$svc" | grep -q -- '--network=.*host'; then
            pass "smb-server: service uses --network=host"
        else
            fail "smb-server: expected --network=host in service file"
        fi
    fi

    # Check port 445 is listening
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp | grep -q ':445 '; then
            pass "smb-server: port 445 is listening"
        else
            fail "smb-server: port 445 is not listening"
        fi
    fi

    # Verify smb.conf is loaded correctly inside the container
    local testparm_out
    testparm_out=$(wl_exec smb-server testparm -s 2>&1 || echo "")
    if echo "$testparm_out" | grep -qi 'testshare'; then
        pass "smb-server: testshare present in smbd config"
    else
        fail "smb-server: testshare not found in smbd config"
        echo "  testparm output: $testparm_out"
    fi

    # SMB share access — try connecting to the share directly
    if command -v smbclient >/dev/null 2>&1; then
        # smbclient needs /var/lib/samba/lock on the host side
        mkdir -p /var/lib/samba/lock 2>/dev/null || true

        # Try direct share access (more reliable than -L listing for non-root smbd)
        local access_out
        access_out=$(smbclient //localhost/testshare -N -c 'ls' 2>&1 || echo "")
        if echo "$access_out" | grep -qE 'blocks|available'; then
            pass "smb-server: testshare accessible via smbclient"
        else
            # Try with guest auth
            access_out=$(smbclient //localhost/testshare -U guest% -c 'ls' 2>&1 || echo "")
            if echo "$access_out" | grep -qE 'blocks|available'; then
                pass "smb-server: testshare accessible via smbclient (guest auth)"
            else
                fail "smb-server: testshare not accessible via smbclient"
                echo "  smbclient -N: $access_out"
                # Also try share listing for diagnostics
                local shares
                shares=$(smbclient -L localhost -N 2>&1 || echo "")
                echo "  smbclient -L: $shares"
                echo "  --- smbd journal ---"
                journalctl -u workload-smb-server.service --no-pager -n 20 2>/dev/null || true
            fi
        fi
    fi
}
