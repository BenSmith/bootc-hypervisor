# Bash completion for workloadctl
# Install to /usr/share/bash-completion/completions/workloadctl

_workload_ctl_completion() {
    local cur prev words cword
    _init_completion || return

    local commands="backup build catalog cleanup clone cp create diagnose disable drift duplicate edit enable exec health images incant info init list logs reboot recreate restart restore rollback secret shell start stats status stop update validate help"
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
    # with three reserved suffixes (setup/pod/net) that are not containers.
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
            | grep -Ev '^(setup|pod|net|build|virtiofs-.*)$')
        if [[ -z "$containers" ]]; then
            return
        fi
        COMPREPLY=( $(compgen -P "${wl}/" -W "$containers" -- "$ctr_prefix") )
    }

    # Get list of credential names (without path)
    local credentials=""
    if [[ -d "$credstore_dir" ]]; then
        credentials=$(cd "$credstore_dir" 2>/dev/null && ls -1 2>/dev/null)
    fi

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
            # First arg: bundle name; then --as NAME
            if [[ "$cur" == -* || "$prev" == "init" && $cword -gt 2 ]]; then
                COMPREPLY=( $(compgen -W "--as" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$bundles" -- "$cur") )
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
            # Complete with workload names (no extra flags)
            COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
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
                local wl="${words[2]}"
                local toml="/etc/workloads.d/${wl}.toml"
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
                COMPREPLY=( $(compgen -W "--list" -- "$cur") )
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
            # Complete with workload names
            COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
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
            # Complete with --purge, --dry-run, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--purge --dry-run" -- "$cur") )
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
            # Complete with --force, --all, --dry-run, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --all --dry-run" -- "$cur") )
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
                COMPREPLY=( $(compgen -W "--image --enable --network --ports --volumes --device --gpu --input --audio --virtualization --groups --systemd --shm-size --cpu-quota --cpu-weight --memory-max --memory-high --memory-swap-max --io-weight --tasks-max" -- "$cur") )
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
                        # Complete with flags or credential name
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--file --force --key-type" -- "$cur") )
                        elif [[ "$prev" == "--file" ]]; then
                            _filedir
                        elif [[ "$prev" == "--key-type" ]]; then
                            COMPREPLY=( $(compgen -W "tpm2 host host+tpm2" -- "$cur") )
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
        help)
            # No completion needed
            return 0
            ;;
    esac
}

complete -o bashdefault -F _workload_ctl_completion workloadctl
