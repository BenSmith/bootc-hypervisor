# Bash completion for workloadctl
# Install to /usr/share/bash-completion/completions/workloadctl

_workload_ctl_completion() {
    local cur prev words cword
    _init_completion || return

    local commands="backup build catalog cleanup clone cp create diagnose disable doctor drift duplicate edit egress enable exec health images incant info init install list logs pcap reboot recreate restart restore rollback secret shell start stats status stop update validate"
    local workload_dir="/etc/workloads.d"
    local credstore_dir="/etc/credstore.encrypted"
    local bundles_dir="/usr/share/workloadctl/workloads"

    # Shippable bundle names (a dir containing workload.toml)
    local bundles=""
    if [[ -d "$bundles_dir" ]]; then
        bundles=$(cd "$bundles_dir" 2>/dev/null && for d in */; do [[ -f "${d}workload.toml" ]] && echo "${d%/}"; done)
    fi

    # Get list of workload names (subdir layout: <name>/workload.toml)
    local workloads=""
    if [[ -d "$workload_dir" ]]; then
        workloads=$(cd "$workload_dir" 2>/dev/null && for d in */; do [[ -f "${d}workload.toml" ]] && echo "${d%/}"; done)
    fi

    # For commands that accept <workload>/<container>: if $cur looks like
    # "name/partial", offer container names from the loaded systemd units
    # for that workload. The unit naming is workload-<name>-<container>.service,
    # sharing that shape with the generator's own helper units, which are not
    # containers: setup/pod/net/build, a VM's proxy, and virtiofs-<tag>. The
    # authoritative list is docs/workload-run-files.md — a helper added there and
    # not here is offered as if it were a container, and `exec`s into nothing.
    # If no per-container units exist, this is a single-container workload —
    # the "/" form doesn't apply, so we return no completions.
    _workloadctl_ref_complete() {
        local ref="$1"
        if [[ "$ref" != */* ]]; then
            COMPREPLY=( $(compgen -W "$workloads" -- "$ref") )
            return
        fi
        local wl="${ref%%/*}"
        local ctr_prefix="${ref#*/}"
        local containers
        containers=$(systemctl list-unit-files --no-legend "workload-${wl}-*.service" 2>/dev/null \
            | awk '{print $1}' \
            | sed -E "s/^workload-${wl}-//;s/\\.service$//" \
            | grep -Ev '^(setup|pod|net|build|proxy|inspect|resolve|virtiofs-.*)$')
        if [[ -z "$containers" ]]; then
            return
        fi
        COMPREPLY=( $(compgen -P "${wl}/" -W "$containers" -- "$ctr_prefix") )
    }

    # Credential names, from two sources unioned.
    #
    # A listing of $credstore_dir is the authoritative set, but it only works in
    # a root shell: the dir is 0700 root, and completion for `sudo workloadctl
    # ...` runs as the UNPRIVILEGED user (bash-completion's sudo handler
    # re-dispatches to this function without elevating). Since every name-taking
    # secret subcommand requires root, and is therefore nearly always typed
    # behind sudo, that source alone completed to nothing in normal use.
    #
    # So also harvest the names workloads REFERENCE, out of world-readable
    # (0755/0644) $workload_dir/*/workload.toml: ${SECRET:name} env refs and
    # `credential = "name"` in [secrets].files entries — the same two shapes
    # auto_detect_credentials() scans. Those are the names you actually type,
    # and it's the only source that can offer a name to `secret create`, which
    # by definition doesn't exist in the credstore yet.
    #
    # Deliberately approximate: an escaped `$${SECRET:name}` ref is inert but
    # still harvested, and a credential with no reference anywhere is only
    # offered when the credstore is readable. Over-offering a name costs a
    # wrong tab-complete; under-offering costs every tab-complete.
    local credentials=""
    if [[ -r "$credstore_dir" ]]; then
        credentials=$(cd "$credstore_dir" 2>/dev/null && ls -1 2>/dev/null)
    fi
    credentials+=$'\n'$(grep -rhoE \
        '\$\{SECRET:[a-zA-Z0-9_-]+\}|credential[[:space:]]*=[[:space:]]*"[a-zA-Z0-9_-]+"' \
        "$workload_dir"/*/workload.toml 2>/dev/null \
        | sed -E 's/^\$\{SECRET:(.*)\}$/\1/; s/^credential[[:space:]]*=[[:space:]]*"(.*)"$/\1/')
    credentials=$(printf '%s\n' $credentials | sort -u)

    # First argument: complete commands
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    # Second argument: depends on the command
    case "${words[1]}" in
        backup)
            # Complete with --all, --output, --consistency, --json, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--all --output --consistency --json" -- "$cur") )
            elif [[ "$prev" == "--consistency" ]]; then
                COMPREPLY=( $(compgen -W "cold crash" -- "$cur") )
            elif [[ "$prev" == "--output" || "$prev" == "-o" ]]; then
                _filedir
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        cleanup)
            # Complete with --apply or --json
            COMPREPLY=( $(compgen -W "--apply --json" -- "$cur") )
            return 0
            ;;
        catalog)
            COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            return 0
            ;;
        init)
            # First arg: bundle name; then --as NAME. --scratch/--scratch-vm
            # take no bundle at all, but offering them alongside costs nothing.
            if [[ "$cur" == -* || "$prev" == "init" && $cword -gt 2 ]]; then
                COMPREPLY=( $(compgen -W "--as --scratch --scratch-vm" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$bundles" -- "$cur") )
            fi
            return 0
            ;;
        install)
            # A source directory containing workload.toml
            _filedir -d
            return 0
            ;;
        doctor)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        egress)
            # Flags, then the workload. The closed vocabularies are completed
            # from the same values cmd_egress validates against; --reason takes
            # a substring, so there is nothing finite to offer for it.
            if [[ "$prev" == "--decision" ]]; then
                COMPREPLY=( $(compgen -W "forward drop" -- "$cur") )
            elif [[ "$prev" == "--mode" ]]; then
                COMPREPLY=( $(compgen -W "forward terminate splice h2" -- "$cur") )
            elif [[ "$prev" == "--plane" ]]; then
                COMPREPLY=( $(compgen -W "tls cleartext" -- "$cur") )
            elif [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-n --lines -g --group --json --id
                    --decision --mode --plane --reason --host --method
                    --status --since --until" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        pcap)
            # Flags, then <workload>[/<container>], then a BPF filter we cannot
            # usefully complete. --list and --stop are the two that change what
            # the positional means, but both still take a workload.
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-i --interface -D --list-interfaces
                    -Q --direction -s --snapshot-length -w --write --detach
                    -c --packet-count -C --rotate-size -W --file-count
                    -G --rotate-seconds --duration --max-size -n -q --quiet
                    --json --dry-run --list --stop" -- "$cur") )
            elif [[ "$prev" == "-i" || "$prev" == "--interface" ]]; then
                COMPREPLY=( $(compgen -W "host guest" -- "$cur") )
            elif [[ "$prev" == "-Q" || "$prev" == "--direction" ]]; then
                COMPREPLY=( $(compgen -W "in out inout" -- "$cur") )
            elif [[ "$prev" == "-w" || "$prev" == "--write" ]]; then
                _filedir
            elif [[ $cword -eq 2 ]]; then
                _workloadctl_ref_complete "$cur"
            fi
            return 0
            ;;
        duplicate|clone)
            # Source and destination are workload names
            COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            return 0
            ;;
        diagnose)
            # Complete with --json or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        build|reboot|recreate)
            # Complete with the mutating-verb flags, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-q --quiet --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        edit)
            # cword 2: workload name; cword 3+: optional control file or -y/--yes
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-y --yes" -- "$cur") )
            elif [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            elif [[ $cword -eq 3 ]]; then
                # Offer common bundle control file names
                # The subdir layout, <name>/workload.toml — this read used to
                # name a flat <name>.toml, which no longer exists, so `bundle`
                # was never found and a renamed instance (init --as, duplicate)
                # silently completed against a bundle dir that is not its own.
                local wl="${words[2]}"
                local toml="${workload_dir}/${wl}/workload.toml"
                local bundle_name="$wl"
                if [[ -f "$toml" ]]; then
                    local b
                    b=$(grep -oP '(?<=bundle = ")[^"]+' "$toml" 2>/dev/null)
                    [[ -n "$b" ]] && bundle_name="$b"
                fi
                local bundle_dir="$bundles_dir/$bundle_name"
                local control_files
                if [[ -d "$bundle_dir" ]]; then
                    control_files=$(cd "$bundle_dir" && find . -type f ! -name "workload.toml" -printf '%P\n' 2>/dev/null)
                fi
                COMPREPLY=( $(compgen -W "$control_files" -- "$cur") )
            fi
            return 0
            ;;
        incant)
            # cword 2: <workload> or <workload>/<container>; then passthrough args
            if [[ $cword -eq 2 ]]; then
                _workloadctl_ref_complete "$cur"
            fi
            return 0
            ;;
        rollback)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--list -q --quiet --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        shell)
            # Accepts <workload> or <workload>/<container>, plus --console
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--console" -- "$cur") )
            else
                _workloadctl_ref_complete "$cur"
            fi
            return 0
            ;;
        enable|start|stop|restart)
            # Complete with the mutating-verb flags, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-q --quiet --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        exec)
            # cword 2: <workload> or <workload>/<container>; then command args
            if [[ $cword -eq 2 ]]; then
                _workloadctl_ref_complete "$cur"
            else
                _filedir
            fi
            return 0
            ;;
        health)
            # Accepts <workload> or <workload>/<container>, plus --json
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                _workloadctl_ref_complete "$cur"
            fi
            return 0
            ;;
        info)
            # Complete with --files, --json, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--files --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        status|drift)
            # Complete with --json or workload names (workload is optional)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        disable)
            # Complete with --purge, --dry-run, the mutating-verb flags, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--purge --dry-run -q --quiet --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        logs)
            # Flags, or <workload>[/<container>]
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-f --follow -n --lines --since" -- "$cur") )
            else
                _workloadctl_ref_complete "$cur"
            fi
            return 0
            ;;
        update)
            # Complete with --force, --all, --dry-run, the mutating-verb flags, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --all --dry-run -q --quiet --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        validate)
            # Complete with --all, --json, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--all --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        stats)
            # Complete with -f, --follow, --json, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-f --follow --json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        images)
            # Complete with list or prune subcommands, or --json
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "list prune" -- "$cur") )
            fi
            return 0
            ;;
        list)
            # Complete with --json flag
            COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            return 0
            ;;
        create)
            # Complete with flags for create command
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--image --enable --init --network --ports --volumes --device --gpu --input --audio --virtualization --groups --systemd --shm-size --cpu-quota --cpu-weight --memory-max --memory-high --memory-swap-max --io-weight --tasks-max" -- "$cur") )
            elif [[ "$prev" == "--gpu" ]]; then
                COMPREPLY=( $(compgen -W "amd nvidia none" -- "$cur") )
            elif [[ "$prev" == "--systemd" ]]; then
                COMPREPLY=( $(compgen -W "always true false" -- "$cur") )
            elif [[ "$prev" == "--network" ]]; then
                COMPREPLY=( $(compgen -W "host pasta none" -- "$cur") )
            fi
            return 0
            ;;
        secret)
            # Complete with subcommands
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "create list delete show rotate export import" -- "$cur") )
            elif [[ $cword -ge 3 ]]; then
                case "${words[2]}" in
                    create)
                        # Complete with flags or credential name. The name pool
                        # here is the referenced-by-a-workload set: creating a
                        # credential is almost always satisfying a ${SECRET:...}
                        # a bundle already demands, and getting it letter-exact
                        # is the whole point (a typo'd name fails at unit start).
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--file --force --key-type" -- "$cur") )
                        elif [[ "$prev" == "--file" ]]; then
                            _filedir
                        elif [[ "$prev" == "--key-type" ]]; then
                            COMPREPLY=( $(compgen -W "tpm2 host host+tpm2" -- "$cur") )
                        else
                            COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        fi
                        ;;
                    delete)
                        # Complete with existing credential names or --force
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--force" -- "$cur") )
                        else
                            COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        fi
                        ;;
                    show)
                        # Complete with existing credential names
                        COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        ;;
                    rotate)
                        # Complete with existing credential names or --key-type
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--key-type" -- "$cur") )
                        elif [[ "$prev" == "--key-type" ]]; then
                            COMPREPLY=( $(compgen -W "tpm2 host host+tpm2" -- "$cur") )
                        else
                            COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        fi
                        ;;
                    list)
                        COMPREPLY=( $(compgen -W "--json" -- "$cur") )
                        ;;
                    export)
                        # Complete with credential names, --output, or passphrase flags
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--output --passphrase-file --passphrase-stdin" -- "$cur") )
                        elif [[ "$prev" == "--output" || "$prev" == "-o" ]]; then
                            _filedir
                        elif [[ "$prev" == "--passphrase-file" ]]; then
                            _filedir
                        else
                            COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        fi
                        ;;
                    import)
                        # Complete with credential name, then file, or flags
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--force --key-type --passphrase-file --passphrase-stdin" -- "$cur") )
                        elif [[ "$prev" == "--key-type" ]]; then
                            COMPREPLY=( $(compgen -W "tpm2 host host+tpm2" -- "$cur") )
                        elif [[ "$prev" == "--passphrase-file" ]]; then
                            _filedir
                        elif [[ $cword -eq 4 ]]; then
                            _filedir secret
                        else
                            # cword 3: the credential name to import AS
                            COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        fi
                        ;;
                esac
            fi
            return 0
            ;;
        restore)
            # Complete with --force, --enable, or .tar.zst files
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --enable" -- "$cur") )
            else
                _filedir tar.zst
            fi
            return 0
            ;;
        cp)
            # Complete with workload:path syntax or files
            _filedir
            return 0
            ;;
    esac
}

complete -o bashdefault -F _workload_ctl_completion workloadctl
