# Bash completion for workloadctl
# Install to /usr/share/bash-completion/completions/workloadctl

_workload_ctl_completion() {
    local cur prev words cword
    _init_completion || return

    local commands="attach backup cleanup cp create disable edit enable exec health images info list logs network ports ps reboot recreate restore rollback secret shell start stats status stop update uid-map validate verify help"
    local workload_dir="/etc/workloads.d"
    local credstore_dir="/etc/credstore.encrypted"

    # Get list of workload names (without .toml extension)
    local workloads=""
    if [[ -d "$workload_dir" ]]; then
        workloads=$(cd "$workload_dir" 2>/dev/null && ls -1 *.toml 2>/dev/null | sed 's/\.toml$//')
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
            | grep -Ev '^(setup|pod|net)$')
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
            # Complete with --all, --output, --no-stop, --json, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--all --output --no-stop --json" -- "$cur") )
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
        uid-map|verify)
            # Complete with --json or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        attach|edit|reboot|recreate|rollback)
            # Complete with workload names (no extra flags)
            COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            return 0
            ;;
        shell)
            # Accepts <workload> or <workload>/<container>
            _workloadctl_ref_complete "$cur"
            return 0
            ;;
        enable|start|stop)
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
        info|ports)
            # Complete with --json or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        status)
            # Complete with --json or workload names (workload is optional)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
            fi
            return 0
            ;;
        disable)
            # Complete with --purge or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--purge" -- "$cur") )
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
            # Complete with --force, --all, or workload names
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --all" -- "$cur") )
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
        ps|list)
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
        network)
            # Positional args: subcommand network_name workload
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "create" -- "$cur") )
            elif [[ $cword -eq 4 ]]; then
                COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
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
                        # Complete with credential names or --output
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--output" -- "$cur") )
                        elif [[ "$prev" == "--output" || "$prev" == "-o" ]]; then
                            _filedir
                        else
                            COMPREPLY=( $(compgen -W "$credentials" -- "$cur") )
                        fi
                        ;;
                    import)
                        # Complete with credential name, then file, or flags
                        if [[ "$cur" == -* ]]; then
                            COMPREPLY=( $(compgen -W "--force --key-type" -- "$cur") )
                        elif [[ "$prev" == "--key-type" ]]; then
                            COMPREPLY=( $(compgen -W "tpm2 host host+tpm2" -- "$cur") )
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

complete -F _workload_ctl_completion workloadctl
