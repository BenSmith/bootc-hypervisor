# Bash completion for workload-ctl
# Install to /usr/share/bash-completion/completions/workload-ctl

_workload_ctl_completion() {
    local cur prev words cword
    _init_completion || return

    local commands="disable enable exec list logs ps restart shell status help"
    local workload_dir="/etc/workloads.d"

    # Get list of workload names (without .toml extension)
    local workloads=""
    if [[ -d "$workload_dir" ]]; then
        workloads=$(cd "$workload_dir" 2>/dev/null && ls -1 *.toml 2>/dev/null | sed 's/\.toml$//')
    fi

    # First argument: complete commands
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    # Second argument: depends on the command
    case "${words[1]}" in
        enable|restart|status|shell|exec|logs)
            # Complete with workload names
            COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
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
        list|ps|help)
            # No completion needed
            return 0
            ;;
    esac

    # Third argument for disable: workload name after --purge
    if [[ $cword -eq 3 && "${words[1]}" == "disable" && "${words[2]}" == "--purge" ]]; then
        COMPREPLY=( $(compgen -W "$workloads" -- "$cur") )
        return 0
    fi
}

complete -F _workload_ctl_completion workload-ctl
